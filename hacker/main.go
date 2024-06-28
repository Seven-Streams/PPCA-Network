package main

import (
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
)

func ReadRootCA() (Root *x509.Certificate) {
	certPEM, err := os.ReadFile("../rootCA.crt")
	if err != nil {
		log.Fatalf("Failed to read certificate file: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		log.Fatal("Failed to decode PEM block containing the certificate")
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse certificate: %v", err)
		return
	}
	Root = cert
	return
}

func main() {
	root := ReadRootCA()

}
