package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"log"
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

type client struct {
	pingpong.PingPongClient

	URL *url.URL `env:"URL,default=https://pong.my-org.internal:4433/"`

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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var cli client
	if err := envdecode.Decode(&cli); err != nil {
		log.Fatal(err)
	}

	if err := pki.Init(); err != nil {
		log.Fatal(err)
	}

	creds := credentials.NewTLS(cli.tlsConfig())
	conn, err := grpc.Dial(cli.URL.Host, grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatal(err)
	}
	cli.PingPongClient = pingpong.NewPingPongClient(conn)

	msg := &pingpong.Message{Payload: "ping!"}
	log.Printf("send: %s", msg.Payload)

	if msg, err = cli.ServePingPong(ctx, msg); err != nil {
		log.Fatal(err)
	}

	log.Printf("recv: %s", msg.Payload)
}

func (c *client) tlsConfig() *tls.Config {
	return &tls.Config{
		VerifyConnection: c.verifyConnection,
		RootCAs:          anchor.Certs.CertPool(),

		GetClientCertificate: (&clientManager{
			Name: c.ClientName,

			Manager: &autocert.Manager{
				Prompt:      autocert.AcceptTOS,
				HostPolicy:  autocert.HostWhitelist(c.ClientName),
				RenewBefore: 12 * time.Hour,

				Client: &acme.Client{
					DirectoryURL: c.ACME.URL.String(),
				},

				ExternalAccountBinding: &acme.ExternalAccountBinding{
					KID: c.ACME.EAB.KID,
					Key: c.ACME.EAB.Key,
				},
			},
		}).getClientCertificate,
	}
}

func (c *client) verifyConnection(cs tls.ConnectionState) error {
	anchorCAs, err := anchor.Certs.Select(anchor.ByType(anchor.AnchorCA))
	if err != nil {
		return err
	}

	opts := x509.VerifyOptions{
		DNSName:       c.ServerName,
		Roots:         anchorCAs.CertPool(),
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, cert := range cs.PeerCertificates[1:] {
		opts.Intermediates.AddCert(cert)
	}

	_, err = cs.PeerCertificates[0].Verify(opts)
	return err
}

type clientManager struct {
	*autocert.Manager

	Name string
}

func (c *clientManager) getClientCertificate(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	chi := &tls.ClientHelloInfo{
		ServerName:       c.Name,
		SignatureSchemes: cri.SignatureSchemes,
	}

	return c.GetCertificate(chi)
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
