package main

import (
	"fmt"
	"net"
	"runtime"
	"time"
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
		parsed := "[" + net.IP(buffer[4:20]).String() + "]"
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
				parsed := "[" + net.IP(buffer[4:20]).String() + "]"
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
