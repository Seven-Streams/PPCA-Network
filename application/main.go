package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
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

type Combind struct {
	host string
	port int
}

var replace string
var to_replace string

func udplisten(udpln net.UDPConn, source Combind) {
	mapping := make(map[Combind]bool)
	defer udpln.Close()
	buffer := make([]byte, 102400)
	for {
		ddl := time.Now().Add(60 * time.Second)
		udpln.SetDeadline(ddl)
		n, from, err := udpln.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		combinded := &Combind{host: from.IP.String(), port: from.Port}
		if combinded == &source {
			var host string
			var port int
			if buffer[3] == 0x01 {
				ip := buffer[4:8]
				host = fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
				port = int(buffer[8])<<8 | int(buffer[9])
				buffer = buffer[10:n]
				n -= 10
			} else if buffer[3] == 0x03 {
				length := int(buffer[4])
				host = string(buffer[5 : 5+length])
				port = int(buffer[5+length])<<8 | int(buffer[6+length])
				buffer[3] = 0x01
				buffer = buffer[7+length : n]
				n -= (7 + length)
			} else if buffer[3] == 0x04 {
				parsed := net.ParseIP(string(buffer[4:20]))
				host = string(parsed)
				port = int(buffer[20])<<8 | int(buffer[21])
				buffer[3] = 0x01
				buffer = buffer[22:n]
				n -= 22
			}
			target := fmt.Sprintf("%s:%d", host, port)
			resolved_addr, err := net.ResolveUDPAddr("udp", target)
			to := &Combind{host: host, port: port}
			mapping[*to] = true
			if err != nil {
				return
			}
			remote_conn, err := net.DialUDP("udp", nil, resolved_addr)
			if err != nil {
				return
			}
			defer remote_conn.Close()
			remote_conn.Write(buffer[:n])
		} else {
			if buffer[0] == 0x00 && buffer[1] == 0x00 && (buffer[3] == 0x03 || buffer[3] == 0x01 || buffer[3] == 0x04) {
				continue
			} else {
				if from.IP.To4() != nil {
					host := from.IP.To4()
					port := from.Port
					header := []byte{0x00, 0x00, 0x00, 0x01, host[0], host[1], host[2], host[3], byte(port >> 8), byte(port & 0xff)}
					buffer = append(header, buffer...)
					n += 10
				} else {
					host := from.IP.To16()
					port := from.Port
					header := []byte{0x00, 0x00, 0x00, 0x04, host[0], host[1], host[2], host[3], host[4], host[5], host[6], host[7], host[8], host[9], host[10], host[11], host[12], host[13], host[14], host[15], byte(port >> 8), byte(port & 0xff)}
					buffer = append(header, buffer...)
					n += 22
				}
				target := fmt.Sprintf("%s:%d", source.host, source.port)
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
	}
}
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
	} else if buffer[1] == 0x03 {
		HandleUDP(conn, buffer, n)
	} else {
		panic("Unsupported method.")
	}
}

func Proxy() {
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

func Proxy24626() {
	ln, err := net.Listen("tcp", "localhost:24626") //listen on port 24625
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

func HandleClient(conn net.Conn) {
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
		go HandleClient(conn)
	}
}

func ParseHTTPSRequest(stream []byte) (host string) {
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

func ParseHTTPRequest(request string) (host string, err error) {
	reader := bufio.NewReader(strings.NewReader(request))
	first_line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	http_reg, err := regexp.Compile("HTTP")
	if err != nil {
		return
	}
	if !http_reg.MatchString(first_line) {
		err = errors.New("not HTTP")
		return
	}
	for {
		line, err_1 := reader.ReadString('\n')
		if err_1 != nil || strings.TrimSpace(line) == "" {
			err = err_1
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
func HandleClientHttp(conn net.Conn) {
	whitelist := "../white.txt"
	blacklist := "../black.txt"
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
	if err != nil {
		return
	}
	host, err := ParseHTTPRequest(string(buffer[:n]))
	if err != nil {
		host = ParseHTTPSRequest(buffer[:n])
	}
	if FileExists(blacklist) {
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
	if FileExists(whitelist) {
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
		go HandleClientHttp(conn)
	}
}

func HandleClientIp(conn net.Conn) {
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
		parsed := net.ParseIP(string(buffer[4:20]))
		host = string(parsed)
	}
	if FileExists(blacklist) {
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
	if FileExists(whitelist) {
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
		go HandleClientIp(conn)
	}
}

func HandleClientPid(conn net.Conn) {
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
		parsed := net.ParseIP(string(buffer[4:20]))
		host = string(parsed)
	}
	if FileExists(blacklist) {
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
	if FileExists(whitelist) {
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
		go HandleClientPid(conn)
	}
}

func FileExists(filename string) bool {
	file, err := os.Open(filename)
	if os.IsNotExist(err) {
		return false
	}
	defer file.Close()
	return err == nil
}

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
		panic(1)
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
		panic(1)
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
	target := string(fmt.Sprintf("%s:%d", host, port))
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
		go handleConnection(conn)
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
			reg_encode, err := regexp.Compile("Accept-Encoding:")
			flag := false
			if err != nil {
				return
			}
			var new_buffer string
			new_buffer += line
			for err == nil {
				line, err = reader.ReadString('\n')
				if (!reg_encode.MatchString(line)) && (!flag) {
					flag = true
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
			count := bytes.Count(buffer, []byte(to_replace))
			buffer = bytes.Replace(buffer, []byte(to_replace), []byte(replace), -1)
			n += count * (len(replace) - len(to_replace))
			file.Write(buffer[:n])
		} //捕获
		conn_send.Write(buffer[:n])
	}
}

func ModifyHttp() {
	fmt.Println("Please input the content which will be replaced.")
	fmt.Scan(&to_replace)
	fmt.Println("Please input the content which replace the previous input.")
	fmt.Scan(&replace)
	ln, err := net.Listen("tcp", "localhost:24626") //listen on port 24626
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			panic(err)
		}
		go HandleConnectionModifyHttp(conn)
	}
}

func HandleUDP(conn net.Conn, buffer []byte, n int) {
	addr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		return
	}
	udpln, err := net.ListenUDP("udp", addr)
	if err != nil {
		return
	}
	var host string
	var port int
	if buffer[3] == 0x01 {
		ip := buffer[4:8]
		host = fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
		port = int(buffer[8])<<8 | int(buffer[9])
	} else if buffer[3] == 0x03 {
		length := int(buffer[4])
		host = string(buffer[5 : 5+length])
		port = int(buffer[5+length])<<8 | int(buffer[6+length])
	} else if buffer[3] == 0x04 {
		parsed := net.ParseIP(string(buffer[4:20]))
		host = string(parsed)
		port = int(buffer[20])<<8 | int(buffer[21])
	}
	from := &Combind{host: host, port: port}
	go udplisten(*udpln, *from)
	response2 := []byte{0x05, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, byte(addr.Port >> 8), byte(addr.Port & 0xff)}
	conn.Write(response2)
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

func HandleMulti1(conn net.Conn) {
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
		go HandleMulti1(conn)
	}
}

func HandleMulti2(conn net.Conn) {
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
		go HandleMulti2(conn)
	}
}

func HandleMulti3(conn net.Conn) {
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
	go io.Copy(new_conn, conn)
	io.Copy(conn, new_conn)
}

func Multi3() {

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
		go HandleMulti3(conn)
	}
}

func HandleReversed(conn net.Conn, addr1 string, addr2 string) {
	server1 := "../server1.txt"
	server2 := "../server2.txt"
	defer conn.Close()
	buffer := make([]byte, 10240)
	n, err := conn.Read(buffer)
	if err != nil {
		return
	}
	host, err := ParseHTTPRequest(string(buffer[:n]))
	if err != nil {
		host = ParseHTTPSRequest(buffer[:n])
	}
	if FileExists(server1) {
		file, err := os.Open(server1)
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
				new_conn, err := net.Dial("tcp", addr1)
				if err != nil {
					return
				}
				defer new_conn.Close()
				new_conn.Write(buffer[:n])
				go io.Copy(conn, new_conn)
				io.Copy(new_conn, conn)
			}
		}
		return
	}
	if FileExists(server2) {
		file, err := os.Open(server2)
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
				new_conn, err := net.Dial("tcp", addr2)
				if err != nil {
					return
				}
				defer new_conn.Close()
				new_conn.Write(buffer[:n])
				go io.Copy(conn, new_conn)
				io.Copy(new_conn, conn)
			}
		}
		return
	}
}

func Reversed() {

	fmt.Println("Please input the servers.")
	var server1, server2 string
	fmt.Scan(&server1)
	fmt.Scan(&server2)
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
		go HandleReversed(conn, server1, server2)
	}
}

func HandleConnectionModifyHttp(conn net.Conn) {
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

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	var op string
	fmt.Println("Please select the mode.")
	fmt.Println("To run a proxy, input\"p\".")
	fmt.Println("To run a forward client, input\"c\".")
	fmt.Println("To run a reversed client, input\"r\".")
	fmt.Println("To perform a TLS Hijacking, input\"j\".")
	fmt.Println("To perform a Http Tampering, input\"t\".")
	fmt.Println("To run a Multi-level proxy, input\"m\".")
	fmt.Scan(&op)
	switch op {
	case "p":
		{
			fmt.Println("The proxy runs on the port 24626.")
			Proxy24626()
		}
	case "c":
		{
			fmt.Println("Please select the rules.")
			fmt.Println("To use IP rules, input\"i\".")
			fmt.Println("To use HTTP and HTTPS rules, input\"h\".")
			fmt.Println("To use TLS rules, input\"t\".")
			fmt.Println("To use Programs rules, input\"p\".")
			fmt.Println("Input\"n\" if you don't want to use any rules.")
			var rule string
			fmt.Scan(&rule)
			switch rule {
			case "i":
				{
					fmt.Println("The files are \"black_ip.txt\" and \"white_ip.txt\"")
					fmt.Println("The server runs on the port 24626.")
					go Proxy()
					ClientIp()
				}
			case "h":
				{
					fmt.Println("The files are \"black_http.txt\" and \"white_http.txt\".")
					fmt.Println("The server runs on the port 24626.")
					go Proxy()
					ClientHttp()
				}
			case "p":
				{
					fmt.Println("The files are \"black_pid.txt\" and \"white_pid.txt\".")
					fmt.Println("The server runs on the port 24626.")
					go Proxy()
					ClientPid()
				}
			case "n":
				{
					fmt.Println("The server runs on the port 24626.")
					go Proxy()
					Client()
				}
			default:
				{
					panic("Invalid input!")
				}
			}
		}
	case "r":
		{
			fmt.Println("The server runs on the port 26426.")
			Reversed()
		}
	case "j":
		{
			fmt.Println("The server runs on the port 26426.")
			Kidnapper()
		}
	case "t":
		{
			fmt.Println("The server runs on the port 26426.")
			ModifyHttp()
		}
	case "m":
		{
			fmt.Println("The server runs on the port 26426.")
			go Multi2()
			go Multi3()
			Multi1()
		}
	default:
		{
			panic("Wrong input!")
		}
	}
}
