package main

import (
	"crypto/tls"
	"log"
	"net"
	"os"
)

func Pass(conn_receive net.Conn, conn_send net.Conn, buffer []byte, filename string) {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0666)
	if err != nil {
		return
	}
	defer file.Close()
	for {
		n, err := conn_receive.Read(buffer)
		if err != nil {
			return
		}
		file.Write(buffer[:n])
		conn_send.Write(buffer[:n])
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	file, err := os.OpenFile("../target", os.O_RDONLY, 0666)
	if err != nil {
		return
	}
	target := make([]byte, 1024)
	n, err := file.Read(target)
	if err != nil {
		return
	}
	remote_conn, err := net.Dial("tcp", string(target[:n]))
	if err != nil {
		return
	}
	defer remote_conn.Close()
	buffer := make([]byte, 1024000)
	remote_buffer := make([]byte, 102400)
	go Pass(conn, remote_conn, buffer, "From.txt")
	Pass(remote_conn, conn, remote_buffer, "Receive.txt")
}

func main() {
	cer, err := tls.LoadX509KeyPair("../hacker/domain.crt", "../hacker/domain.key")
	if err != nil {
		log.Fatal(err)
	}
	config := &tls.Config{Certificates: []tls.Certificate{cer}}
	ln, err := tls.Listen("tcp", "localhost:24626", config)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConnection(conn)
	}
}
