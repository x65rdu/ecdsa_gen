// this is the utility to generage public and private ECDSA NIST P-384 keys,
// run it by `$go run ecdsa_gen.go` or compile by `$go build ecdsa_gen.go`
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"reflect"
)

var privateFName, publicFName string

func init() {
	flag.StringVar(&privateFName, "pr", "private.pem", "private key file name: WILL BE OVERWRITTEN!")
	flag.StringVar(&publicFName, "pu", "public.pem", "public key file name: WILL BE OVERWRITTEN!")
	flag.Parse()
}

func main() {
	// generating keys
	pri, pub, err := generate()
	if err != nil {
		log.Fatal(err)
	}
	// encoding keys to store in a file
	encPri, encPub, err := encode(pri, pub)
	if err != nil {
		log.Fatal(err)
	}
	// cleanup current folder in case of an error
	defer func() {
		if err != nil {
			if err = cleanup(); err != nil {
				log.Fatal(err)
			}
		}
	}()
	// store in the current folder
	if err = store(encPri, encPub); err != nil {
		log.Print(err)
		return
	}
	// check stored keys
	if err = check(pri, pub); err != nil {
		log.Print(err)
		return
	}
	log.Printf("%q, %q were added to the current folder", privateFName, publicFName)
}

func generate() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	pri, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pub := &pri.PublicKey
	return pri, pub, err
}

func encode(pri *ecdsa.PrivateKey, pub *ecdsa.PublicKey) ([]byte, []byte, error) {
	x509Pri, err := x509.MarshalECPrivateKey(pri)
	if err != nil {
		return nil, nil, err
	}
	pemPri := pem.EncodeToMemory(&pem.Block{Type: "ECDSA PRIVATE KEY", Bytes: x509Pri})
	x509Pub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	pemPub := pem.EncodeToMemory(&pem.Block{Type: "ECDSA PUBLIC KEY", Bytes: x509Pub})
	return pemPri, pemPub, nil
}

func decode(pri []byte, pub []byte) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	pemBlock, _ := pem.Decode(pri)
	priDec, err := x509.ParseECPrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	pemBlock, _ = pem.Decode(pub)
	if err != nil {
		return nil, nil, err
	}
	genericPub, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	pubDec, ok := genericPub.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("can not assert the public key")
	}
	return priDec, pubDec, nil
}

func store(pri []byte, pub []byte) error {
	if err := ioutil.WriteFile(privateFName, pri, 0755); err != nil {
		return err
	}
	if err := ioutil.WriteFile(publicFName, pub, 0755); err != nil {
		return err
	}
	return nil
}

func get() ([]byte, []byte, error) {
	pri, err := ioutil.ReadFile(privateFName)
	if err != nil {
		return nil, nil, err
	}
	pub, err := ioutil.ReadFile(publicFName)
	if err != nil {
		return nil, nil, err
	}
	return pri, pub, nil
}

func check(pri *ecdsa.PrivateKey, pub *ecdsa.PublicKey) error {
	// receiving from the current folder
	encPri, encPub, err := get()
	if err != nil {
		return err
	}
	// decoding keys
	decPri, decPub, err := decode(encPri, encPub)
	if err != nil {
		return err
	}
	// comparing keys
	if !reflect.DeepEqual(pri, decPri) {
		return fmt.Errorf("private keys dont match")
	}
	if !reflect.DeepEqual(pub, decPub) {
		fmt.Errorf("public keys dont match")
	}
	return nil
}

func cleanup() error {
	log.Printf("removing %q, %q from current folder", privateFName, publicFName)
	if err := os.Remove(privateFName); err != nil {
		return err
	}
	if err := os.Remove(publicFName); err != nil {
		return err
	}
	return nil
}
