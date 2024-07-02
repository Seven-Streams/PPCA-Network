package main

import (
	"bufio"
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
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

func HandleConnectionProxy(conn net.Conn) {
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
	if buffer[3] == 0x01 {
		ip := buffer[4:8]
		host = fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
	} else if buffer[3] == 0x03 {
		host = string(buffer[5 : n-2])
	} else if buffer[3] == 0x04 {
		parsed := net.ParseIP(string(buffer[4:20]))
		host = string(parsed)
	}
	port := int(buffer[n-2])<<8 | int(buffer[n-1])
	fmt.Printf(fmt.Sprintf("%s:%d\n", host, port))
	new_conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return
	}
	localAddr := new_conn.LocalAddr().(*net.TCPAddr)
	localPort := localAddr.Port
	firstByte := byte(localPort >> 8)
	secondByte := byte(localPort & 0xFF)
	defer new_conn.Close()
	response = []byte{0x05, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, firstByte, secondByte}
	fmt.Println(response)
	_, err = conn.Write(response)
	if err != nil {
		return
	}
	go io.Copy(new_conn, conn)
	io.Copy(conn, new_conn)
}
func HandleConnectionProxyWithUDP(conn net.Conn) {
	defer conn.Close()
	buffer := make([]byte, 102400)
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
	if buffer[2] != 0x00 {
		panic("Unsupported reserved field")
	}
	if buffer[1] == 0x01 {
		HandleTCP(conn, buffer, n)
	} else if buffer[3] == 0x03 {
		handleUDP(conn, buffer, n)
	} else {
		panic("Unsupported method.")
	}
}

func proxy() {
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
		go HandleConnectionProxy(conn)
	}
}

func ProxySupportUDP() {
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
		go HandleConnectionProxyWithUDP(conn)
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()
	remote_conn, err := net.Dial("tcp", "localhost:24625") //dial to the server.
	if err != nil {
		return
	}
	defer remote_conn.Close()
	go io.Copy(remote_conn, conn)
	io.Copy(conn, remote_conn)
}

func Client() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	ln, err := net.Listen("tcp", ":24626") //listen on port 24626
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			panic(err)
		}
		go handleClient(conn)
	}
}

func parseHTTPRequest(request string) (host string) {
	reader := bufio.NewReader(strings.NewReader(request))
	_, _ = reader.ReadString('\n')
	for {
		line, err := reader.ReadString('\n')
		if err != nil || strings.TrimSpace(line) == "" {
			break
		}
		if len(line) <= 6 {
			continue
		}
		if string(line[0:6]) == "Host: " {
			fmt.Println(string(line[6:]))
			host = string(line[6:])
			return
		}
	}
	return
}

func handleClientHttp(conn net.Conn) {
	whitelist := "../white_http.txt"
	blacklist := "../black_http.txt"
	defer conn.Close()
	remote_conn, err := net.Dial("tcp", "127.0.0.1:24625") //dial to the server.
	if err != nil {
		return
	}
	buffer := make([]byte, 10240)
	remote_buffer := make([]byte, 10240)
	n, err := conn.Read(buffer) //the first pack.
	if err != nil {
		return
	}
	_, err = remote_conn.Write(buffer[:n]) //pass the first pack.
	if err != nil {
		return
	}
	n, err = remote_conn.Read(remote_buffer) //get the first reply.
	if err != nil {
		return
	}
	_, err = conn.Write(remote_buffer[:n]) //pass the first reply.
	if err != nil {
		return
	}
	n, err = conn.Read(buffer)
	if err != nil {
		return
	}
	request := make([]byte, n)
	copy(request, buffer[:n])
	response := []byte{0x05, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x00}
	conn.Write([]byte(response))
	n, err = conn.Read(buffer)
	host := parseHTTPRequest(string(buffer[:n]))
	if err != nil {
		return
	}
	if fileExists(blacklist) {
		file, err := os.Open(blacklist)
		if err != nil {
			return
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			expr, err := regexp.Compile(scanner.Text())
			if err != nil {
				return
			}
			if expr.MatchString(host) {
				return
			}
		}
	}
	if fileExists(whitelist) {
		file, err := os.Open(whitelist)
		if err != nil {
			return
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			expr, err := regexp.Compile(scanner.Text())
			if err != nil {
				return
			}
			if expr.MatchString(host) {
				remote_conn.Close()
				port := int(buffer[n-2])<<8 | int(buffer[n-1])

				remote_conn, err = net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
				if err != nil {
					return
				}
				defer remote_conn.Close()
				remote_conn.Write(buffer[:n])
				go io.Copy(remote_conn, conn)
				io.Copy(conn, remote_conn)
				return
			}
		}
	}
	remote_conn.Write(request)      //To send the true request.
	remote_conn.Read(remote_buffer) //Ignore the reply.
	defer remote_conn.Close()
	remote_conn.Write(buffer[:n])
	go io.Copy(remote_conn, conn)
	io.Copy(conn, remote_conn)
}

func ClientHttp() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	ln, err := net.Listen("tcp", ":24626") //listen on port 24626
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			panic(err)
		}
		go handleClientHttp(conn)
	}
}

func handleClientIp(conn net.Conn) {
	whitelist := "../white_ip.txt"
	blacklist := "../black_ip.txt"
	defer conn.Close()
	remote_conn, err := net.Dial("tcp", "127.0.0.1:24625") //dial to the server.
	if err != nil {
		return
	}
	buffer := make([]byte, 1024)
	remote_buffer := make([]byte, 1024)
	n, err := conn.Read(buffer) //the first pack.
	if err != nil {
		return
	}
	_, err = remote_conn.Write(buffer[:n]) //pass the first pack.
	if err != nil {
		return
	}
	n, err = remote_conn.Read(remote_buffer) //get the first reply.
	if err != nil {
		return
	}
	_, err = conn.Write(remote_buffer[:n]) //pass the first reply.
	if err != nil {
		return
	}
	n, err = conn.Read(buffer)
	if err != nil {
		return
	}
	var host string
	if buffer[3] == 0x01 {
		ip := buffer[4:8]
		host = fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
	} else if buffer[3] == 0x03 {
		host = string(buffer[5 : n-2])
	} else if buffer[3] == 0x04 {
		ipv6Bytes := buffer[4:20]
		host = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
			ipv6Bytes[0], ipv6Bytes[1], ipv6Bytes[2], ipv6Bytes[3],
			ipv6Bytes[4], ipv6Bytes[5], ipv6Bytes[6], ipv6Bytes[7],
			ipv6Bytes[8], ipv6Bytes[9], ipv6Bytes[10], ipv6Bytes[11],
			ipv6Bytes[12], ipv6Bytes[13], ipv6Bytes[14], ipv6Bytes[15])
	}
	if fileExists(blacklist) {
		file, err := os.Open(blacklist)
		if err != nil {
			return
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			expr, err := regexp.Compile(scanner.Text())
			if err != nil {
				return
			}
			if expr.MatchString(host) {
				return
			}
		}
	}
	if fileExists(whitelist) {
		file, err := os.Open(whitelist)
		if err != nil {
			return
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			expr, err := regexp.Compile(scanner.Text())
			if err != nil {
				return
			}
			if expr.MatchString(host) {
				remote_conn.Close()
				port := int(buffer[n-2])<<8 | int(buffer[n-1])

				remote_conn, err = net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
				if err != nil {
					return
				}
				defer remote_conn.Close()
				go io.Copy(remote_conn, conn)
				io.Copy(conn, remote_conn)
				return
			}
		}
	}
	remote_conn.Write(buffer[:n])
	defer remote_conn.Close()
	go io.Copy(remote_conn, conn)
	io.Copy(conn, remote_conn)
}

func ClientIp() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	ln, err := net.Listen("tcp", ":24626") //listen on port 24626
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			panic(err)
		}
		go handleClientIp(conn)
	}
}

func handleClientPid(conn net.Conn) {
	whitelist := "../white_pid.txt"
	blacklist := "../black_pid.txt"
	from := conn.RemoteAddr().String()
	parts := strings.Split(from, ":")
	port := parts[len(parts)-1]
	cmd := exec.Command("lsof", "-i", ":"+port)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return
	}
	output := out.String()
	reader := bufio.NewReader(strings.NewReader(output))
	_, err = reader.ReadString('\n')
	if err != nil {
		return
	}
	command_line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	slices := strings.Fields(command_line)
	name := slices[0]
	println(name)
	defer conn.Close()
	remote_conn, err := net.Dial("tcp", "127.0.0.1:24625") //dial to the server.
	if err != nil {
		return
	}
	buffer := make([]byte, 1024)
	remote_buffer := make([]byte, 1024)
	n, err := conn.Read(buffer) //the first pack.
	if err != nil {
		return
	}
	_, err = remote_conn.Write(buffer[:n]) //pass the first pack.
	if err != nil {
		return
	}
	n, err = remote_conn.Read(remote_buffer) //get the first reply.
	if err != nil {
		return
	}
	_, err = conn.Write(remote_buffer[:n]) //pass the first reply.
	if err != nil {
		return
	}
	n, err = conn.Read(buffer)
	if err != nil {
		return
	}
	var host string
	if buffer[3] == 0x01 {
		ip := buffer[4:8]
		host = fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
	} else if buffer[3] == 0x03 {
		host = string(buffer[5 : n-2])
	} else if buffer[3] == 0x04 {
		ipv6Bytes := buffer[4:20]
		host = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
			ipv6Bytes[0], ipv6Bytes[1], ipv6Bytes[2], ipv6Bytes[3],
			ipv6Bytes[4], ipv6Bytes[5], ipv6Bytes[6], ipv6Bytes[7],
			ipv6Bytes[8], ipv6Bytes[9], ipv6Bytes[10], ipv6Bytes[11],
			ipv6Bytes[12], ipv6Bytes[13], ipv6Bytes[14], ipv6Bytes[15])
	}
	if fileExists(blacklist) {
		file, err := os.Open(blacklist)
		if err != nil {
			return
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			expr, err := regexp.Compile(scanner.Text())
			if err != nil {
				return
			}
			if expr.MatchString(name) {
				return
			}
		}
	}
	if fileExists(whitelist) {
		file, err := os.Open(whitelist)
		if err != nil {
			return
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			expr, err := regexp.Compile(scanner.Text())
			if err != nil {
				return
			}
			if expr.MatchString(name) {
				remote_conn.Close()
				port := int(buffer[n-2])<<8 | int(buffer[n-1])

				remote_conn, err = net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
				if err != nil {
					return
				}
				defer remote_conn.Close()
				go io.Copy(remote_conn, conn)
				io.Copy(conn, remote_conn)
				return
			}
		}
	}
	remote_conn.Write(buffer[:n])
	defer remote_conn.Close()
	go io.Copy(remote_conn, conn)
	io.Copy(conn, remote_conn)
}

func ClientPid() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	ln, err := net.Listen("tcp", ":24626") //listen on port 24626
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			panic(err)
		}
		go handleClientPid(conn)
	}
}

func parseHTTPSRequest(stream []byte) (host string) {
	upper := len(stream)
	ptr := 43
	ptr += int(stream[ptr]) //std 75
	ptr++                   // std 76
	length := (int(stream[ptr]) << 8) | (int(stream[ptr+1]))
	ptr += length           //std 108
	ptr += 2                //std 110
	ptr += int(stream[ptr]) // std 111
	ptr++                   //std 112
	ptr += 2                // std 114
	for ptr < upper {
		index := (int(stream[ptr]) << 8) | (int(stream[ptr+1]))
		if index != 0 {
			ptr += 2 // to the length bit.
			part_len := (int(stream[ptr]) << 8) | (int(stream[ptr+1]))
			ptr += part_len
			ptr += 2
		} else {
			ptr += 7
			host_len := (int(stream[ptr]) << 8) | (int(stream[ptr+1]))
			host = string(stream[ptr:(ptr + host_len)])
			return
		}
	}
	return
}

func fileExists(filename string) bool {
	file, err := os.Open(filename)
	if os.IsNotExist(err) {
		return false
	}
	defer file.Close()
	return err == nil
}

func handleClientTls(conn net.Conn) {
	whitelist := "../white_tls.txt"
	blacklist := "../black_tls.txt"
	defer conn.Close()
	remote_conn, err := net.Dial("tcp", "localhost:24625") //dial to the server.
	if err != nil {
		return
	}
	buffer := make([]byte, 10240)
	remote_buffer := make([]byte, 10240)
	n, err := conn.Read(buffer) //the first pack.
	if err != nil {
		return
	}
	_, err = remote_conn.Write(buffer[:n]) //pass the first pack.
	if err != nil {
		return
	}
	n, err = remote_conn.Read(remote_buffer) //get the first reply.
	if err != nil {
		return
	}
	_, err = conn.Write(remote_buffer[:n]) //pass the first reply.
	if err != nil {
		return
	}
	n, err = conn.Read(buffer)
	if err != nil {
		return
	}
	request := make([]byte, n)
	copy(request, buffer[:n])
	response := []byte{0x05, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x00}
	conn.Write([]byte(response))
	n, err = conn.Read(buffer)
	host := parseHTTPSRequest(buffer[:n])
	if err != nil {
		return
	}
	if fileExists(blacklist) {
		file, err := os.Open(blacklist)
		if err != nil {
			return
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			expr, err := regexp.Compile(scanner.Text())
			if err != nil {
				return
			}
			if expr.MatchString(host) {
				return
			}
		}
	}
	if fileExists(whitelist) {
		file, err := os.Open(whitelist)
		if err != nil {
			return
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			expr, err := regexp.Compile(scanner.Text())
			if err != nil {
				return
			}
			if expr.MatchString(host) {
				remote_conn.Close()
				port := int(buffer[n-2])<<8 | int(buffer[n-1])

				remote_conn, err = net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
				if err != nil {
					return
				}
				defer remote_conn.Close()
				remote_conn.Write(buffer[:n])
				go io.Copy(remote_conn, conn)
				io.Copy(conn, remote_conn)
				return
			}
		}
	}
	remote_conn.Write(request)      //To send the true request.
	remote_conn.Read(remote_buffer) //Ignore the reply.
	defer remote_conn.Close()
	remote_conn.Write(buffer[:n])
	go io.Copy(remote_conn, conn)
	io.Copy(conn, remote_conn)
}

func ClientTls() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	ln, err := net.Listen("tcp", ":24626") //listen on port 24626
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			panic(err)
		}
		go handleClient(conn)
	}
}

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

func handleConnectionKidnapper2(conn net.Conn, config *tls.Config) {
	defer conn.Close()
	file, err := os.OpenFile("../target_address.txt", os.O_RDONLY, 0666)
	if err != nil {
		return
	}
	target := make([]byte, 1024)
	n, err := file.Read(target)
	if err != nil {
		return
	}
	file.Close()
	remote_conn, err := tls.Dial("tcp", string(target[:(n-1)]), config)
	if err != nil {
		return
	}
	defer remote_conn.Close()
	buffer := make([]byte, 102400)
	remote_buffer := make([]byte, 102400)
	go Pass(conn, remote_conn, buffer, "From.txt")
	Pass(remote_conn, conn, remote_buffer, "Receive.txt")
}

func MyTls(ln net.Listener, config *tls.Config) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
		}
		go handleConnectionKidnapper2(conn, config)
	}
}

func CreateMyCert(domain string) {
	private_key_file, err := os.ReadFile("domain.key")
	if err != nil {
		return
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
		DNSNames: []string{domain},
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, private_key)
	if err != nil {
		return
	}
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return
	}
	caCertPEM, err := os.ReadFile("rootCA.crt")
	if err != nil {
		return
	}
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		return
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return
	}

	caKeyPEM, err := os.ReadFile("rootCA.key")
	if err != nil {
		return
	}
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return
	}
	caKey, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return
	}
	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: domain,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &certTemplate, caCert, csr.PublicKey, caKey)
	if err != nil {
		panic(err)
	}
	certPEMBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}
	certFile, err := os.OpenFile("domain.crt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		panic(err)
	}
	defer certFile.Close()
	err = pem.Encode(certFile, certPEMBlock)
	if err != nil {
		return
	}
}

func handleConnectionKidnapper(conn net.Conn) {
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
	if buffer[3] == 0x01 {
		ip := buffer[4:8]
		host = fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
	} else if buffer[3] == 0x03 {
		host = string(buffer[5 : n-2])
	} else if buffer[3] == 0x04 {
		parsed := net.ParseIP(string(buffer[4:20]))
		host = string(parsed)
	}
	port := int(buffer[n-2])<<8 | int(buffer[n-1])
	target := string(fmt.Sprintf("%s:%d\n", host, port))
	CreateMyCert(host)
	cer, err := tls.LoadX509KeyPair("../hacker/domain.crt", "../hacker/domain.key")
	if err != nil {
		log.Fatal(err)
	}
	config := &tls.Config{Certificates: []tls.Certificate{cer}}
	ln, err := tls.Listen("tcp", ":0", config)
	if err != nil {
		log.Fatal(err)
	}
	go MyTls(ln, config)
	file, err := os.OpenFile("../target_address.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		return
	}
	file.Write([]byte(target))
	file.Close()
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

func Kidnapper() {
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
		go handleConnectionKidnapper(conn)
	}
}

func PassRecord(conn_receive net.Conn, conn_send net.Conn, buffer []byte, filename string) {
	now := time.Now()
	file, err := os.OpenFile(now.Format("2006-01-02_15-04-05")+filename, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0666)
	if err != nil {
		return
	}
	defer file.Close()
	for {
		conn_receive.SetReadDeadline(time.Now().Add(3 * time.Second))
		conn_send.SetWriteDeadline(time.Now().Add(3 * time.Second))
		n, err := conn_receive.Read(buffer)
		if err != nil {
			return
		}
		reader := bufio.NewReader(strings.NewReader(string(buffer[:n])))
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		reg, err := regexp.Compile("HTTP")
		if err != nil {
			return
		}
		if reg.MatchString(line) {
			reg_encode, err := regexp.Compile("Accept-Encoding:\\s*(.*)")
			if err != nil {
				return
			}
			var new_buffer string
			new_buffer += line
			for err == nil {
				line, err = reader.ReadString('\n')
				if !reg_encode.MatchString(line) {
					new_buffer += line
				}
			}
			new_buffer += "\r\n\r\n"
			file.Write([]byte(new_buffer))
			conn_send.Write([]byte(new_buffer))
		} else { //捕获
			conn_send.Write(buffer[:n])
		}
	}
}

func PassModify(conn_receive net.Conn, conn_send net.Conn, buffer []byte, filename string) {
	now := time.Now()
	file, err := os.OpenFile(now.Format("2006-01-02_15-04-05")+filename, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0666)
	if err != nil {
		return
	}
	defer file.Close()
	for {
		conn_receive.SetReadDeadline(time.Now().Add(3 * time.Second))
		conn_send.SetWriteDeadline(time.Now().Add(3 * time.Second))
		n, err := conn_receive.Read(buffer)
		if err != nil {
			return
		}
		reader := bufio.NewReader(strings.NewReader(string(buffer[:n])))
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		reg, err := regexp.Compile("HTTP")
		if err != nil {
			return
		}

		if reg.MatchString(line) {
			buffer = bytes.Replace(buffer, []byte{'P', 'K', 'U'}, []byte{'S', 'J', 'T', 'U'}, -1)
			file.Write(buffer[:n])
		} //捕获
		conn_send.Write(buffer[:n])
	}
}

func handleConnectionModifyHttp(conn net.Conn) {
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
	if buffer[3] == 0x01 {
		ip := buffer[4:8]
		host = fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
	} else if buffer[3] == 0x03 {
		host = string(buffer[5 : n-2])
	} else if buffer[3] == 0x04 {
		parsed := net.ParseIP(string(buffer[4:20]))
		host = string(parsed)
	}
	port := int(buffer[n-2])<<8 | int(buffer[n-1])
	new_conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return
	}
	localAddr := new_conn.LocalAddr().(*net.TCPAddr)
	localPort := localAddr.Port
	firstByte := byte(localPort >> 8)
	secondByte := byte(localPort & 0xFF)
	defer new_conn.Close()
	response = []byte{0x05, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, firstByte, secondByte}
	fmt.Println(response)
	_, err = conn.Write(response)
	if err != nil {
		return
	}
	defer new_conn.Close()
	new_buffer := make([]byte, 102400)
	remote_buffer := make([]byte, 102400)
	go PassRecord(conn, new_conn, new_buffer, "From.txt")
	PassModify(new_conn, conn, remote_buffer, "Receive.txt")
}

func ModifyHttp() {
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
		go handleConnectionModifyHttp(conn)
	}
}

func handleUDP(conn net.Conn, buffer []byte, n int) {
	addr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		return
	}
	udpln, err := net.ListenUDP("udp", addr)
	if err != nil {
		return
	}
	localAddr := udpln.LocalAddr().(*net.TCPAddr)
	localPort := localAddr.Port
	firstByte := byte(localPort >> 8)
	secondByte := byte(localPort & 0xFF)
	response2 := []byte{0x05, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, firstByte, secondByte}
	conn.Write(response2)
	defer udpln.Close()
	for {
		n, _, err := udpln.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		var host string
		var port int
		if buffer[3] == 0x01 {
			ip := buffer[4:8]
			host = fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
			port = int(buffer[4])<<8 | int(buffer[5])
		} else if buffer[3] == 0x03 {
			length := int(buffer[4])
			host = string(buffer[5 : 5+length])
			port = int(buffer[5+length])<<8 | int(buffer[6+length])
		} else if buffer[3] == 0x04 {
			parsed := net.ParseIP(string(buffer[4:20]))
			host = string(parsed)
			port = int(buffer[20])<<8 | int(buffer[21])
		}
		target := fmt.Sprintf("%s:%d", host, port)
		resolved_addr, err := net.ResolveUDPAddr("udp", target)
		if err != nil {
			return
		}
		remote_conn, err := net.DialUDP("udp", nil, resolved_addr)
		if err != nil {
			return
		}
		defer remote_conn.Close()
		remote_conn.Write(buffer[:n])
	}
}

func HandleTCP(conn net.Conn, buffer []byte, n int) {
	var host string
	if buffer[3] == 0x01 {
		ip := buffer[4:8]
		host = fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
	} else if buffer[3] == 0x03 {
		host = string(buffer[5 : n-2])
	} else if buffer[3] == 0x04 {
		parsed := net.ParseIP(string(buffer[4:20]))
		host = string(parsed)
	}
	port := int(buffer[n-2])<<8 | int(buffer[n-1])
	new_conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return
	}
	localAddr := new_conn.LocalAddr().(*net.TCPAddr)
	localPort := localAddr.Port
	firstByte := byte(localPort >> 8)
	secondByte := byte(localPort & 0xFF)
	defer new_conn.Close()
	response := []byte{0x05, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, firstByte, secondByte}
	fmt.Println(response)
	_, err = conn.Write(response)
	if err != nil {
		return
	}
	go io.Copy(new_conn, conn)
	io.Copy(conn, new_conn)
}

func handleMulti1(conn net.Conn) {
	defer conn.Close()
	remote_conn, err := net.Dial("tcp", "localhost:24625") //dial to the server.
	if err != nil {
		return
	}
	defer remote_conn.Close()
	go io.Copy(remote_conn, conn)
	io.Copy(conn, remote_conn)
}

func Multi1() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	ln, err := net.Listen("tcp", ":24626") //listen on port 24626
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			panic(err)
		}
		go handleMulti1(conn)
	}
}

func handleMulti2(conn net.Conn) {
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
	new_conn, err := net.Dial("tcp", "127.0.0.1:24627")
	if err != nil {
		return
	}
	defer new_conn.Close()
	first_shakehand := []byte{0x05, 0x01, 0x00}
	_, err = new_conn.Write(first_shakehand)
	if err != nil {
		return
	}
	new_buffer := make([]byte, 1024)
	new_conn.Read(new_buffer)
	if new_buffer[0] != 0x05 {
		return
	}
	if new_buffer[1] != 0x00 {
		return
	}
	_, err = new_conn.Write(buffer[:n])
	if err != nil {
		return
	}
	n, err = new_conn.Read(new_buffer)
	if err != nil {
		return
	}
	fmt.Println(response)
	_, err = conn.Write(new_buffer[:n])
	if err != nil {
		return
	}
	go io.Copy(new_conn, conn)
	io.Copy(conn, new_conn)
}

func Multi2() {
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
		go handleMulti2(conn)
	}
}

func handleMulti3(conn net.Conn) {
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
	if buffer[3] == 0x01 {
		ip := buffer[4:8]
		host = fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
	} else if buffer[3] == 0x03 {
		host = string(buffer[5 : n-2])
	} else if buffer[3] == 0x04 {
		parsed := net.ParseIP(string(buffer[4:20]))
		host = string(parsed)
	}
	port := int(buffer[n-2])<<8 | int(buffer[n-1])
	fmt.Printf(fmt.Sprintf("%s:%d\n", host, port))
	new_conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return
	}
	localAddr := new_conn.LocalAddr().(*net.TCPAddr)
	localPort := localAddr.Port
	firstByte := byte(localPort >> 8)
	secondByte := byte(localPort & 0xFF)
	defer new_conn.Close()
	response = []byte{0x05, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, firstByte, secondByte}
	fmt.Println(response)
	_, err = conn.Write(response)
	if err != nil {
		return
	}
	go io.Copy(new_conn, conn)
	io.Copy(conn, new_conn)
}

func Multi3() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	ln, err := net.Listen("tcp", "localhost:24627") //listen on port 24627
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			panic(err)
		}
		go handleMulti3(conn)
	}
}

func main() {

}
