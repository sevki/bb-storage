package spire

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"io/fs"
	"os"
)


func HasSpireEndpoint() bool {
	s := os.Getenv(workloadapi.SocketEnv)
	if s == "" {
		return false
	}
	fi, err := os.Stat(s)
	if err != nil {
		return false
	}
	if fi.Mode().Type()&fs.ModeSocket != 0 {
		return true
	}
	return false
}

func GetTLSClientConfig() (*tls.Config, error) {
	src, err := workloadapi.NewX509Source(context.Background())
	if err != nil {
		return nil, err
	}

	tlsConfig := tlsconfig.MTLSClientConfig(src, src, tlsconfig.AuthorizeAny())
	return tlsConfig, nil
}

func GetTLSServerConfig() (*tls.Config, error) {
	src, err := workloadapi.NewX509Source(context.Background())
	if err != nil {
		return nil, err
	}

	tlsConfig := tlsconfig.MTLSServerConfig(src, src, tlsconfig.AuthorizeAny())
	return tlsConfig, nil
}
