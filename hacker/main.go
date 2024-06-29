package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
)

func CreateMyCert(domain string) {
	my_file, err := os.OpenFile("domain.ext", os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		panic(err)
	}
	defer my_file.Close()
	my_file.Write([]byte("authorityKeyIdentifier=keyid,issuer\n"))
	my_file.Write([]byte("basicConstraints=CA:FALSE\n"))
	my_file.Write([]byte("subjectAltName = @alt_names\n"))
	my_file.Write([]byte("[alt_names]\n"))
	my_file.Write([]byte("DNS.1 = " + domain))
	cmd := exec.Command("bash", "-c", "openssl req -key domain.key -new -out domain.csr")
	var stdinBuffer bytes.Buffer
	stdinBuffer.WriteString("CN\n")
	stdinBuffer.WriteString("Shanghai\n")
	stdinBuffer.WriteString("Shanghai\n")
	stdinBuffer.WriteString("Hackers\n")
	stdinBuffer.WriteString("Hackers\n")
	stdinBuffer.WriteString(domain + "\n")
	stdinBuffer.WriteString("sb\n")
	stdinBuffer.WriteString("\n\n")
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return
	}

	go func() {
		defer stdinPipe.Close()
		stdinPipe.Write(stdinBuffer.Bytes())
	}()
	cmd = exec.Command("bash", "-c", "openssl x509 -req -CA rootCA.crt -CAkey rootCA.key -in domain.csr -out domain.crt -days 365 -CAcreateserial -extfile domain.ext")
	cmd.Run()
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
		ipv6Bytes := buffer[4:20]
		host = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
			ipv6Bytes[0], ipv6Bytes[1], ipv6Bytes[2], ipv6Bytes[3],
			ipv6Bytes[4], ipv6Bytes[5], ipv6Bytes[6], ipv6Bytes[7],
			ipv6Bytes[8], ipv6Bytes[9], ipv6Bytes[10], ipv6Bytes[11],
			ipv6Bytes[12], ipv6Bytes[13], ipv6Bytes[14], ipv6Bytes[15])
	}
	port := int(buffer[n-2])<<8 | int(buffer[n-1])
	target := string(fmt.Sprintf("%s:%d\n", host, port))
	CreateMyCert(host)
	file, err := os.OpenFile("../target_address.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		return
	}
	file.Write([]byte(target))
	file.Close()
	new_conn, err := net.Dial("tcp", "localhost:24626")
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
