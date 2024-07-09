package main

import (
	"bytes"
	"fmt"
	"net"
	"runtime"
)

type Combind struct {
	host string
	port int
}

func handleConnection(conn net.Conn) {
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
	_, err = conn.Read(buffer)
	if err != nil {
		return
	}
	if buffer[0] != 0x05 {
		panic("Unsupported SOCKS version")
	}
	if buffer[1] != 0x03 {
		panic("Unsupported command")
	}
	if buffer[2] != 0x00 {
		panic("Unsupported reserved field")
	}
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

func udplisten(udpln net.UDPConn, source Combind) {
	mapping := make(map[Combind]bool)
	mapping[source] = true
	defer udpln.Close()
	buffer := make([]byte, 102400)
	for {
		n, from, err := udpln.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		combinded := &Combind{host: from.IP.String(), port: from.Port}
		to_update := []byte{from.IP[0], from.IP[1], from.IP[2], from.IP[3], byte(from.Port >> 8), byte(from.Port & 0xff)}
		_, exist := mapping[*combinded]
		if !exist {
			continue
		}
		var host string
		var port int
		if buffer[3] == 0x01 {
			ip := buffer[4:8]
			host = fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
			port = int(buffer[8])<<8 | int(buffer[9])
			buffer = bytes.Replace(buffer, buffer[4:10], to_update, 1)
		} else if buffer[3] == 0x03 {
			length := int(buffer[4])
			host = string(buffer[5 : 5+length])
			port = int(buffer[5+length])<<8 | int(buffer[6+length])
			buffer[3] = 0x01
			buffer = bytes.Replace(buffer, buffer[4:(7+length)], to_update, 1)
		} else if buffer[3] == 0x04 {
			parsed := net.ParseIP(string(buffer[4:20]))
			host = string(parsed)
			port = int(buffer[20])<<8 | int(buffer[21])
			buffer[3] = 0x01
			buffer = bytes.Replace(buffer, buffer[4:22], to_update, 1)
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
	}
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
