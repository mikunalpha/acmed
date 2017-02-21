package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/crypto/acme"
)

var (
	defaultConfigDir = "./"

	defaultAddress = "0.0.0.0:4402"

	defaultDisco = "https://acme-staging.api.letsencrypt.org/directory"

	defaultEmail = "email@example.com"

	defaultRemaining = uint64(21)

	defaultBundle = true

	rsaPrivateKey = "RSA PRIVATE KEY"
	ecPrivateKey  = "EC PRIVATE KEY"
	x509PublicKey = "CERTIFICATE"
)

type config struct {
	Server configServer `json:"server"`
}

type configServer struct {
	Address *string           `json:"address"`
	Webs    []configServerWeb `json:"webs"`
}

type configServerWeb struct {
	Email     *string `json:"email"`
	Domain    *string `json:"domain"`
	Disco     *string `json:"disco"`
	Remaining *uint64 `json:"remaining"`
	Bundle    *bool   `json:"bundle"`
}

// readConfigFile reads configuration of acmed from a file named acmed.json.
func readConfigFile() *config {
	c := config{}

	b, err := ioutil.ReadFile(filepath.Join(defaultConfigDir, "acmed.json"))
	if err != nil {
		log.Fatalln(err)
		return nil
	}
	if err := json.Unmarshal(b, &c); err != nil {
		log.Fatalf("acmed config: %s\n", err)
		return nil
	}

	return &c
}

// anyKey reads the key from file or generates a new one if gen == true.
// It returns an error if filename exists but cannot be read.
// A newly generated key is also stored to filename.
func anyKey(filename string, gen bool) (crypto.Signer, error) {
	k, err := readKey(filename)
	if err == nil {
		return k, nil
	}
	if !os.IsNotExist(err) || !gen {
		return nil, err
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return ecKey, writeKey(filename, ecKey)
}

// readKey reads a private rsa key from path.
// The key is expected to be in PEM format.
func readKey(path string) (crypto.Signer, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	d, _ := pem.Decode(b)
	if d == nil {
		return nil, fmt.Errorf("no block found in %q", path)
	}
	switch d.Type {
	case rsaPrivateKey:
		return x509.ParsePKCS1PrivateKey(d.Bytes)
	case ecPrivateKey:
		return x509.ParseECPrivateKey(d.Bytes)
	default:
		return nil, fmt.Errorf("%q is unsupported", d.Type)
	}
}

// writeKey writes k to the specified path in PEM format.
// If file does not exists, it will be created with 0600 mod.
func writeKey(path string, k *ecdsa.PrivateKey) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	bytes, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return err
	}
	b := &pem.Block{Type: ecPrivateKey, Bytes: bytes}
	if err := pem.Encode(f, b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// accountConfig is configuration for a single ACME CA account.
type accountConfig struct {
	acme.Account
	CA string `json:"ca"` // CA discovery URL

	// key is stored separately
	key crypto.Signer
}

// readAccountConfig reads userConfig from path and a private key.
// It expects to find the key at the same location,
// by replacing path extention with ".key".
//func readAccountConfig(name string) (*userConfig, error) {
func readAccountConfig(domain string) (*accountConfig, error) {
	b, err := ioutil.ReadFile(filepath.Join(filepath.Dir(defaultConfigDir), domain, "account.json"))
	if err != nil {
		return nil, err
	}
	ac := &accountConfig{}
	if err := json.Unmarshal(b, ac); err != nil {
		return nil, err
	}
	if key, err := readKey(filepath.Join(defaultConfigDir, "webs", domain, "account.key")); err == nil {
		ac.key = key
	}
	return ac, nil
}

// writeAccountConfig writes ac to a file specified by path, creating paret dirs
// along the way. If file does not exists, it will be created with 0600 mod.
// This function does not store ac.key.
func writeAccountConfig(domain string, ac *accountConfig) error {
	b, err := json.MarshalIndent(ac, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(filepath.Dir(defaultConfigDir), "webs", domain), 0755); err != nil {
		return err
	}
	return ioutil.WriteFile(filepath.Join(filepath.Dir(defaultConfigDir), "webs", domain, "account.json"), b, 0600)
}

// readCrt read certificate from file and return it if it is valid.
// The func is came from: https://github.com/google/acme/pull/32
func readCrt(path string) (*x509.Certificate, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	d, _ := pem.Decode(b)
	if d == nil {
		return nil, fmt.Errorf("no block found in %q", path)
	}
	if d.Type != x509PublicKey {
		return nil, fmt.Errorf("%q is unsupported", d.Type)
	}
	return x509.ParseCertificate(d.Bytes)
}
