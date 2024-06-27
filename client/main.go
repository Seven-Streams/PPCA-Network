package main

import (
	"io"
	"net"
	"runtime"
)

func handleClient(conn net.Conn) {
	defer conn.Close()
	buffer := make([]byte, 1024)
	remote_buffer := make([]byte, 1024)
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
	remote_conn, err := net.Dial("TCP", "127.0.0.1:24625") //dial to the server.
	if err != nil {
		return
	}
	remote_conn.Write([]byte(data))
	_, err = remote_conn.Read(remote_buffer)
	if err != nil {
		return
	}
	conn.Write(remote_buffer) //negotiation.
	buffer = buffer[:0]
	remote_buffer = remote_buffer[:0]
	_, err = conn.Read(buffer) // get the request.
	if err != nil {
		return
	}
	_, err = remote_conn.Write(buffer) // pass the request.
	if err != nil {
		return
	}
	_, err = remote_conn.Read(remote_buffer) // get the reply.
	if err != nil {
		return
	}
	_, err = conn.Write(remote_buffer) // pass the reply.
	if err != nil {
		return
	}
	go io.Copy(remote_conn, conn)
	io.Copy(conn, remote_conn)
}

func main() {
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
