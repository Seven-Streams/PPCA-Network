package main

import (
	"fmt"
	"net"
	"runtime"
)

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
			ipv6Bytes := buffer[4:20]
			host = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
				ipv6Bytes[0], ipv6Bytes[1], ipv6Bytes[2], ipv6Bytes[3],
				ipv6Bytes[4], ipv6Bytes[5], ipv6Bytes[6], ipv6Bytes[7],
				ipv6Bytes[8], ipv6Bytes[9], ipv6Bytes[10], ipv6Bytes[11],
				ipv6Bytes[12], ipv6Bytes[13], ipv6Bytes[14], ipv6Bytes[15])
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
