package util

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"path/filepath"
	"strings"
	"time"

	configuration "github.com/buildbarn/bb-storage/pkg/proto/configuration/tls"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type certInfo struct {
	certs   []*x509.Certificate
	key     crypto.PrivateKey
	caCerts *x509.CertPool
}

var cipherSuiteIDs = map[string]uint16{}

func init() {
	// Initialize the map of cipher suite IDs based on the ciphers
	// supported by the Go TLS library.
	for _, cipherSuite := range tls.CipherSuites() {
		cipherSuiteIDs[cipherSuite.Name] = cipherSuite.ID
	}
}

func getBaseTLSConfig(cipherSuites []string) (*tls.Config, error) {
	tlsConfig := tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Resolve all provided cipher suite names.
	for _, cipherSuite := range cipherSuites {
		id, ok := cipherSuiteIDs[cipherSuite]
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument, "Unsupported cipher suite: %#v", cipherSuite)
		}
		tlsConfig.CipherSuites = append(tlsConfig.CipherSuites, id)
	}

	return &tlsConfig, nil
}

// NewTLSConfigFromClientConfiguration creates a TLS configuration
// object based on parameters specified in a Protobuf message for use
// with a TLS client. This Protobuf message is embedded in Buildbarn
// configuration files.
func NewTLSConfigFromClientConfiguration(configuration *configuration.ClientConfiguration) (*tls.Config, error) {
	if configuration == nil {
		return nil, nil
	}

	tlsConfig, err := getBaseTLSConfig(configuration.CipherSuites)
	if err != nil {
		return nil, err
	}
	tlsConfig.ServerName = configuration.ServerName

	var ci *certInfo
	if configuration.ClientCertificate != "" && configuration.ClientPrivateKey != "" {
		if IsPEMFile(configuration.ClientCertificate) && IsPEMFile(configuration.ClientPrivateKey) && IsPEMFile(configuration.ServerCertificateAuthorities) {
			ci, err = newCertInfo(configuration.ClientCertificate, configuration.ClientPrivateKey, configuration.ServerCertificateAuthorities)
			if err != nil {
				return nil, StatusWrapWithCode(err, codes.InvalidArgument, "Invalid client certificate or private key")
			}
			tlsConfig.GetClientCertificate = ci.getClientCertificate(configuration.ClientCertificate, configuration.ClientPrivateKey,
				configuration.ServerCertificateAuthorities)
		} else {
			// Serve a client certificate when provided.
			cert, err := tls.X509KeyPair([]byte(configuration.ClientCertificate), []byte(configuration.ClientPrivateKey))
			if err != nil {
				return nil, StatusWrapWithCode(err, codes.InvalidArgument, "Invalid client certificate or private key")
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
	}

	if IsPEMFile(configuration.ServerCertificateAuthorities) {
		tlsConfig.RootCAs = ci.caCerts
	} else {
		if serverCAs := configuration.ServerCertificateAuthorities; serverCAs != "" {
			// Don't use the default root CA list. Use the ones
			// provided in the configuration instead.
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM([]byte(serverCAs)) {
				return nil, status.Error(codes.InvalidArgument, "Invalid server certificate authorities")
			}
			tlsConfig.RootCAs = pool
		}
	}

	return tlsConfig, nil
}

// NewTLSConfigFromServerConfiguration creates a TLS configuration
// object based on parameters specified in a Protobuf message for use
// with a TLS server. This Protobuf message is embedded in Buildbarn
// configuration files.
func NewTLSConfigFromServerConfiguration(configuration *configuration.ServerConfiguration) (*tls.Config, error) {
	if configuration == nil {
		return nil, nil
	}

	tlsConfig, err := getBaseTLSConfig(configuration.CipherSuites)
	if err != nil {
		return nil, err
	}
	tlsConfig.ClientAuth = tls.RequestClientCert

	// Require the use of server-side certificates.
	if IsPEMFile(configuration.ServerCertificate) && IsPEMFile(configuration.ServerPrivateKey) {
		// Note: Server specifies CA using The grpcServers config authenticationPolicy:
		// { tlsClientCertificate: { clientCertificateAuthorities: "/path/to/ca_certificates.pem" } }
		ci, err := newCertInfo(configuration.ServerCertificate, configuration.ServerPrivateKey, "")
		if err != nil {
			return nil, StatusWrapWithCode(err, codes.InvalidArgument, "Invalid server certificate or private key")
		}
		tlsConfig.GetCertificate = ci.getCertificate(configuration.ServerCertificate, configuration.ServerPrivateKey, "")
	} else {
		cert, err := tls.X509KeyPair([]byte(configuration.ServerCertificate), []byte(configuration.ServerPrivateKey))
		if err != nil {
			return nil, StatusWrapWithCode(err, codes.InvalidArgument, "Invalid server certificate or private key")
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}

// Determine if the string containes the name of a PEM file or its contents (via importstr).
func IsPEMFile(s string) bool {
	return filepath.IsAbs(s) && strings.HasSuffix(strings.ToLower(s), ".pem")
}

func newCertInfo(certFile, keyFile, caCertFile string) (*certInfo, error) {
	ci := &certInfo{}
	err := ci.loadNewCerts(certFile, keyFile, caCertFile)
	if err != nil {
		return nil, err
	}
	return ci, nil
}

func (ci *certInfo) getClientCertificate(certFile, keyFile, caCertFile string) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		if time.Now().After(ci.certs[0].NotAfter.Add(time.Minute * -15)) {
			// Cert is about to expire.  Some external entity is responsible for rotating Certs.
			// Reload the new ones.
			if err := ci.loadNewCerts(certFile, keyFile, caCertFile); err != nil {
				return nil, status.Errorf(codes.FailedPrecondition, "Can't reload certs: %v\n", err)
			}
		}
		return ci.getTLSCert(), nil
	}
}

func (ci *certInfo) getCertificate(certFile, keyFile, caCertFile string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		if time.Now().After(ci.certs[0].NotAfter.Add(time.Minute * -15)) {
			// Cert is about to expire.  Some external entity is responsible for rotating Certs.
			// Reload the new ones.
			if err := ci.loadNewCerts(certFile, keyFile, caCertFile); err != nil {
				return nil, status.Errorf(codes.FailedPrecondition, "Can't reload certs: %v\n", err)
			}
		}
		return ci.getTLSCert(), nil
	}
}

// Load new certs from the file system.
func (ci *certInfo) loadNewCerts(certFile, keyFile, caCertFile string) error {
	b, err := ioutil.ReadFile(certFile)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "Can't read certificate: %v", err)
	}
	certs := []*x509.Certificate{}
	for len(b) != 0 {
		block, rem := pem.Decode(b)
		if block == nil {
			if len(certs) != 0 {
				break
			}
			return status.Errorf(codes.FailedPrecondition, "Can't decode cert: %v", err)
		}
		if block.Type != "CERTIFICATE" {
			if len(certs) != 0 {
				break
			}
			return status.Errorf(codes.FailedPrecondition, "Wrong block type in cert file: %s", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			if len(certs) != 0 {
				break
			}
			return status.Errorf(codes.FailedPrecondition, "Can't parse cert: %v", err)
		}
		certs = append(certs, cert)
		b = rem
	}

	b, err = ioutil.ReadFile(keyFile)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "Can't read key: %v", err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return status.Errorf(codes.FailedPrecondition, "Can't decode key: %v", err)
	}

	// Read and parse the private key file.  NOTE: GCP distributes keys with PKCS#1 headers
	// instead of PKCS#8, but the binary bits are compatible.  Be flexible with the headers.
	if !strings.Contains(block.Type, "PRIVATE KEY") {
		return status.Errorf(codes.FailedPrecondition, "Wrong block type in key file: %s", block.Type)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "Can't parse key: %v", err)
	}

	if caCertFile != "" {
		// Read and parse the CA certificates file.
		b, err = ioutil.ReadFile(caCertFile)
		if err != nil {
			return status.Errorf(codes.FailedPrecondition, "Can't read CA certs: %v", err)
		}
		caCerts := x509.NewCertPool()
		if !caCerts.AppendCertsFromPEM(b) {
			return status.Error(codes.InvalidArgument, "Invalid server certificate authorities")
		}
		ci.caCerts = caCerts
	}
	ci.certs = certs
	ci.key = key
	return nil
}

func (ci *certInfo) getTLSCert() *tls.Certificate {
	cert := &tls.Certificate{
		Certificate: make([][]byte, 0, len(ci.certs)),
		PrivateKey:  ci.key,
	}
	for _, c := range ci.certs {
		cert.Certificate = append(cert.Certificate, c.Raw)
	}
	return cert
}
