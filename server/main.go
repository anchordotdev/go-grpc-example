package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"log"
	"net"
	"net/url"
	"time"

	"github.com/anchordotdev/anchor-go"
	"github.com/joeshaw/envdecode"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"anchor.dev/my-org/my-realm/pki-go"
	"github.com/anchordotdev/go-grpc-example/pingpong"
)

type server struct {
	pingpong.UnimplementedPingPongServer

	Addr string `env:"ADDR,default=:4433"`

	ClientName string `env:"CLIENT_NAME,default=ping.my-org.internal"`
	ServerName string `env:"SERVER_NAME,default=pong.my-org.internal"`

	ACME struct {
		URL *url.URL `env:"ACME_DIRECTORY_URL,required"`

		EAB struct {
			KID string `env:"ACME_KID,required"`
			Key b64    `env:"ACME_HMAC_KEY,required"`
		}
	}
}

func main() {
	var srv server
	if err := envdecode.Decode(&srv); err != nil {
		log.Fatal(err)
	}

	if err := pki.Init(); err != nil {
		log.Fatal(err)
	}

	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		log.Fatal(err)
	}

	gsrv := grpc.NewServer(grpc.Creds(credentials.NewTLS(srv.tlsConfig())))
	pingpong.RegisterPingPongServer(gsrv, &srv)

	log.Fatal(gsrv.Serve(ln))
}

func (s *server) ServePingPong(ctx context.Context, req *pingpong.Message) (*pingpong.Message, error) {
	return &pingpong.Message{Payload: "pong!"}, nil
}

func (s *server) tlsConfig() *tls.Config {
	return &tls.Config{
		VerifyConnection: s.verifyConnection,
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        anchor.Certs.CertPool(),

		GetCertificate: (&autocert.Manager{
			Prompt:      autocert.AcceptTOS,
			HostPolicy:  autocert.HostWhitelist(s.ServerName),
			RenewBefore: 12 * time.Hour,

			Client: &acme.Client{
				DirectoryURL: s.ACME.URL.String(),
			},

			ExternalAccountBinding: &acme.ExternalAccountBinding{
				KID: s.ACME.EAB.KID,
				Key: s.ACME.EAB.Key,
			},
		}).GetCertificate,
	}
}

func (s *server) verifyConnection(cs tls.ConnectionState) error {
	anchorCAs, err := anchor.Certs.Select(anchor.ByType(anchor.AnchorCA))
	if err != nil {
		return err
	}

	opts := x509.VerifyOptions{
		DNSName:       s.ClientName,
		Roots:         anchorCAs.CertPool(),
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	for _, cert := range cs.PeerCertificates[1:] {
		opts.Intermediates.AddCert(cert)
	}

	_, err = cs.PeerCertificates[0].Verify(opts)
	return err
}

type b64 []byte

func (b *b64) UnmarshalText(text []byte) error {
	data, err := base64.RawURLEncoding.DecodeString(string(text))
	if err != nil {
		return err
	}

	*b = data
	return nil
}
