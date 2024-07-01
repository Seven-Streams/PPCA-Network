package main

import (
	"fmt"
	"io"
	"net"
	"runtime"
)

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
