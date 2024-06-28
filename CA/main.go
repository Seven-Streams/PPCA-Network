package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

func main() {
	// 读取证书文件
	certPEM, err := os.ReadFile("../rootCA.crt")
	if err != nil {
		log.Fatalf("Failed to read certificate file: %v", err)
	}

	// 解码PEM证书
	block, _ := pem.Decode(certPEM)
	if block == nil {
		log.Fatal("Failed to decode PEM block containing the certificate")
	}

	// 解析证书
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse certificate: %v", err)
	}

	fmt.Printf("Certificate: %+v\n", cert)
}
