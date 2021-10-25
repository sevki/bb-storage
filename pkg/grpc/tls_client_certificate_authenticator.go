package grpc

import (
	"context"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"time"

	"github.com/buildbarn/bb-storage/pkg/clock"
	"github.com/buildbarn/bb-storage/pkg/proto/configuration/spiffe"
	"github.com/buildbarn/bb-storage/pkg/util"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type tlsClientCertificateAuthenticator struct {
	clientCAs       *x509.CertPool
	clock           clock.Clock
	allowedSubjects *spiffe.SubjectMatcher
	caPathName      string
	caMtime         time.Time
}

// NewTLSClientCertificateAuthenticator creates an Authenticator that
// only grants access in case the client connected to the gRPC server
// using a TLS client certificate that can be validated against the
// chain of CAs used by the server.
func NewTLSClientCertificateAuthenticator(clientCAs *x509.CertPool, clock clock.Clock, allowedSubjects *spiffe.SubjectMatcher,
	caPathName string) Authenticator {
	var mtime time.Time
	if caPathName != "" {
		fi, err := os.Stat(caPathName)
		if err == nil {
			mtime = fi.ModTime()
		} else {
			log.Printf("NewTLSClientCertificateAuthenticator: can't stat %s: %v\n", caPathName, err)
		}
	}
	return &tlsClientCertificateAuthenticator{
		allowedSubjects: allowedSubjects,
		clientCAs:       clientCAs,
		clock:           clock,
		caPathName:      caPathName,
		caMtime:         mtime,
	}
}

func (a *tlsClientCertificateAuthenticator) Authenticate(ctx context.Context) (context.Context, error) {
	// Check if we need to reload CA certs.
	if a.caPathName != "" {
		fi, err := os.Stat(a.caPathName)
		if err == nil {
			mtime := fi.ModTime()
			if  mtime != a.caMtime {
				// CA certs file has changed, so reload it.
				b, err := ioutil.ReadFile(a.caPathName)
				if err != nil {
					log.Printf("Authenticate: can't read caCerts: %v\n", err)
				} else {
					caCerts := x509.NewCertPool()
					if !caCerts.AppendCertsFromPEM(b) {
						log.Println("Authenticate: invalid server certificate authorities")
					} else {
						a.clientCAs = caCerts
						a.caMtime = mtime
					}
				}
			}
		}
	}

	// Extract client certificate chain from the connection.
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "Connection was not established using gRPC")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "Connection was not established using TLS")
	}
	certs := tlsInfo.State.PeerCertificates
	if len(certs) == 0 {
		return nil, status.Error(codes.Unauthenticated, "Client provided no TLS client certificate")
	}

	// Perform certificate verification.
	// TODO: Should this be memoized?
	opts := x509.VerifyOptions{
		Roots:         a.clientCAs,
		CurrentTime:   a.clock.Now(),
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return nil, util.StatusWrapWithCode(err, codes.Unauthenticated, "Cannot validate TLS client certificate")
	}
	if a.allowedSubjects != nil {
		id, err := x509svid.IDFromCert(certs[len(certs)-1])
		if err != nil {
			return nil, util.StatusWrapWithCode(err, codes.Unauthenticated, "Cannot validate TLS client certificate as valid x509svid")
		}
		pattern, ok := a.allowedSubjects.AllowedSpiffeIds[id.TrustDomain().String()]
		if !ok {
			return nil, status.Error(codes.Unauthenticated, fmt.Sprintf("Trustdomain %q is not permitted", id.String()))
		}
		ok, err = path.Match(pattern, id.Path())
		if ok {
			return nil, status.Error(codes.Unauthenticated, fmt.Sprintf("Subject %q is not permitted", id.String()))
		}
		if err != nil {
			return nil, util.StatusWrapWithCode(err, codes.Unauthenticated, "Cannot validate TLS client certificate as valid x509svid")
		}
	}
	return ctx, nil
}
