package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"runtime"
	"time"
)

var replace string
var to_replace string

func Pass(conn_receive net.Conn, conn_send net.Conn, buffer []byte, filename string) {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0666)
	if err != nil {
		return
	}
	defer file.Close()
	for {
		n, err := conn_receive.Read(buffer)
		if filename == "Receive.txt" {
			count := bytes.Count(buffer, []byte(to_replace))
			buffer = bytes.Replace(buffer, []byte(to_replace), []byte(replace), -1)
			n += count * (len(replace) - len(to_replace))
			file.Write(buffer[:n])
		}
		if err != nil {
			return
		}
		file.Write(buffer[:n])
		conn_send.Write(buffer[:n])
	}
}

func handleConnection2(conn net.Conn, config *tls.Config, domain string) {
	defer conn.Close()
	remote_conn, err := tls.Dial("tcp", domain, config)
	if err != nil {
		return
	}
	defer remote_conn.Close()
	buffer := make([]byte, 102400)
	remote_buffer := make([]byte, 102400)
	go Pass(conn, remote_conn, buffer, "From.txt")
	Pass(remote_conn, conn, remote_buffer, "Receive.txt")
}

func MyTls(ln net.Listener, config *tls.Config, domain string) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
		}
		go handleConnection2(conn, config, domain)
	}
}

func CreateMyCert(domain string) (cer tls.Certificate) {
	private_key_file, err := os.ReadFile("domain.key")
	if err != nil {
		panic(err)
	}
	private_key_raw, _ := pem.Decode(private_key_file)
	private_key, err := x509.ParsePKCS8PrivateKey(private_key_raw.Bytes)
	if err != nil {
		panic(err)
	}
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: domain,
		},
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, private_key)
	if err != nil {
		panic(err)
	}
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		panic(err)
	}
	caCertPEM, err := os.ReadFile("rootCA.crt")
	if err != nil {
		panic(err)
	}
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		panic(err)
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		panic(err)
	}
	caKeyPEM, err := os.ReadFile("rootCA.key")
	if err != nil {
		panic(err)
	}
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		panic(err)
	}
	caKey, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		panic(err)
	}
	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: domain,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &certTemplate, caCert, csr.PublicKey, caKey)
	if err != nil {
		panic(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	pri := pem.EncodeToMemory(private_key_raw)
	cer, err = tls.X509KeyPair(certPEM, pri)
	if err != nil {
		panic(err)
	}
	return cer
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return
	}
	data := string(buffer[:n])
	if data[0] != 0x05 {
		panic("Unsupported SOCKS version")
	}
	response := []byte{0x05, 0x00}
	conn.Write(response)
	n, err = conn.Read(buffer)
	if err != nil {
		return
	}
	if buffer[0] != 0x05 {
		panic("Unsupported SOCKS version")
	}
	if buffer[1] != 0x01 {
		panic("Unsupported command")
	}
	if buffer[2] != 0x00 {
		panic("Unsupported reserved field")
	}
	var host string
	port := int(buffer[n-2])<<8 | int(buffer[n-1])
	if buffer[3] == 0x01 {
		ip := buffer[4:8]
		host = fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
	} else if buffer[3] == 0x03 {
		host = string(buffer[5 : n-2])
	} else if buffer[3] == 0x04 {
		ipv6 := buffer[4:20]
		host = "[" + net.IP(ipv6).String() + "]"
	}
	target := fmt.Sprintf("%s:%d\n", host, port)
	cer := CreateMyCert(host)
	config := &tls.Config{Certificates: []tls.Certificate{cer}}
	ln, err := tls.Listen("tcp", ":0", config)
	if err != nil {
		log.Fatal(err)
	}
	go MyTls(ln, config, target)
	time.Sleep(1 * time.Second)
	new_conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return
	}
	localAddr := new_conn.LocalAddr().(*net.TCPAddr)
	localPort := localAddr.Port
	firstByte := byte(localPort >> 8)
	secondByte := byte(localPort & 0xFF)
	defer new_conn.Close()
	response = []byte{0x05, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, firstByte, secondByte}
	_, err = conn.Write(response)
	if err != nil {
		return
	}
	go io.Copy(new_conn, conn)
	io.Copy(conn, new_conn)
}

func main() {
	fmt.Scan(&to_replace)
	fmt.Scan(&replace)
	runtime.GOMAXPROCS(runtime.NumCPU())
	ln, err := net.Listen("tcp", "localhost:24625") //listen on port 24625
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			panic(err)
		}
		go handleConnection(conn)
	}
}
