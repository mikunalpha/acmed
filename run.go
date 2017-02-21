package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/acme"
)

var (
	serverAddress = defaultAddress
)

func runRun(arguments []string) {
	var err error

	c := readConfigFile()
	if c.Server.Address != nil && *c.Server.Address != "" {
		serverAddress = *c.Server.Address
	}
	for i, web := range c.Server.Webs {
		if web.Domain == nil {
			log.Fatalln("Domain of web is required.")
			return
		}
		if web.Email == nil || *web.Email == "" {
			c.Server.Webs[i].Email = &defaultEmail
		}
		if web.Disco == nil || *web.Disco == "" {
			c.Server.Webs[i].Disco = &defaultDisco
		}
		if web.Remaining == nil {
			c.Server.Webs[i].Remaining = &defaultRemaining
		}
		if web.Bundle == nil {
			c.Server.Webs[i].Bundle = &defaultBundle
		}
	}

	serverCommand := flag.NewFlagSet("server", flag.ExitOnError)
	serverAddressFlag := serverCommand.String("p", "", "Address for challenges.")
	serverCommand.Parse(arguments)
	if *serverAddressFlag != "" {
		serverAddress = *serverAddressFlag
	}

	for _, web := range c.Server.Webs {
		err = getCert(web)
		if err != nil {
			fmt.Println(err)
			continue
		}
	}
}

func getCert(c configServerWeb) error {
	var err error

	fmt.Printf("Get cert of %s...\n", *c.Domain)

	ac, err := generateAccountConfig(c)
	if err != nil {
		return err
	}

	// read crt if existent
	crtPath := filepath.Join(defaultConfigDir, "webs", *c.Domain, *c.Domain+".crt")

	crt, err := readCrt(crtPath)
	if err == nil {
		// do not re-issue certificate if it's not about to expire in less than three weeks
		expiresIn := crt.NotAfter.Sub(time.Now())
		if expiresIn > time.Duration(*c.Remaining)*24*time.Hour {
			// errorf("cert of %s is still valid for more than a three weeks, not renewing", cn)
			fmt.Printf("cert of %s is still valid, not renewing\n", *c.Domain)
			return nil
		}
	}

	// read or generate new cert key
	crtKeyPath := filepath.Join(defaultConfigDir, "webs", *c.Domain, *c.Domain+".key")
	crtKey, err := anyKey(crtKeyPath, true)
	if err != nil {
		return err
	}

	// generate CSR now to fail early in case of an error
	req := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: *c.Domain},
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, req, crtKey)
	if err != nil {
		// fatalf("csr: %v", err)/
		return err
	}

	// initialize acme client and start authz flow
	// we only look for http-01 challenges at the moment
	client := &acme.Client{
		Key:          ac.key,
		DirectoryURL: *c.Disco,
	}
	domain := *c.Domain
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	if err := authz(ctx, client, domain); err != nil {
		return fmt.Errorf("%s: %v", domain, err)
	}
	cancel()

	// challenge fulfilled: get the cert
	// wait at most 30 min
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	cert, _, err := client.CreateCert(ctx, csr, 365*12*time.Hour, *c.Bundle)
	if err != nil {
		return fmt.Errorf("%s: %v", domain, err)
	}
	// logf("cert url: %s", curl)
	var pemcert []byte
	for _, b := range cert {
		b = pem.EncodeToMemory(&pem.Block{Type: x509PublicKey, Bytes: b})
		pemcert = append(pemcert, b...)
	}

	if err := ioutil.WriteFile(crtPath, pemcert, 0644); err != nil {
		return fmt.Errorf("%s: %v", domain, err)
	}

	return nil
}

func generateAccountConfig(c configServerWeb) (*accountConfig, error) {
	// get exist account config
	ac, err := readAccountConfig(*c.Domain)
	if err == nil && ac.key != nil {
		if ac.Contact[0] == "mailto:"+*c.Email {
			return ac, nil
		}
	}

	if err := os.MkdirAll(filepath.Join(filepath.Dir(defaultConfigDir), "webs", *c.Domain), 0755); err != nil {
		return nil, err
	}
	key, err := anyKey(filepath.Join(filepath.Dir(defaultConfigDir), "webs", *c.Domain, "account.key"), true)
	if err != nil {
		return nil, err
	}
	ac = &accountConfig{
		Account: acme.Account{Contact: []string{"mailto:" + *c.Email}},
		key:     key,
	}

	client := &acme.Client{
		Key:          ac.key,
		DirectoryURL: *c.Disco,
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	a, err := client.Register(ctx, &ac.Account, acme.AcceptTOS)
	if err != nil {
		return nil, err
	}
	ac.Account = *a
	if err := writeAccountConfig(*c.Domain, ac); err != nil {
		return nil, err
	}

	return ac, nil
}

// This func is modified from https://github.com/google/acme/blob/master/cert.go
func authz(ctx context.Context, client *acme.Client, domain string) error {
	z, err := client.Authorize(ctx, domain)
	if err != nil {
		return err
	}
	if z.Status == acme.StatusValid {
		return nil
	}
	var chal *acme.Challenge
	for _, c := range z.Challenges {
		if c.Type == "http-01" {
			chal = c
			break
		}
	}
	if chal == nil {
		return errors.New("no supported challenge found")
	}

	// respond to http-01 challenge
	ln, err := net.Listen("tcp", serverAddress)
	if err != nil {
		return fmt.Errorf("listen %s: %v", serverAddress, err)
	}
	defer ln.Close()

	val, err := client.HTTP01ChallengeResponse(chal.Token)
	if err != nil {
		return err
	}
	path := client.HTTP01ChallengePath(chal.Token)
	go http.Serve(ln, http01Handler(path, val))

	if _, err := client.Accept(ctx, chal); err != nil {
		return fmt.Errorf("accept challenge: %v", err)
	}
	_, err = client.WaitAuthorization(ctx, z.URI)
	return err
}

func http01Handler(path, value string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			log.Printf("unknown request path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write([]byte(value))
	})
}
