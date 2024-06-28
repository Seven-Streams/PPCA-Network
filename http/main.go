package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"
)

func PassRecord(conn_receive net.Conn, conn_send net.Conn, buffer []byte, filename string) {
	now := time.Now()
	file, err := os.OpenFile(now.Format("2006-01-02_15-04-05")+filename, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0666)
	if err != nil {
		return
	}
	defer file.Close()
	for {
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
			reg_host, err := regexp.Compile("Host:")
			if err != nil {
				return
			}
			reg_agent, err := regexp.Compile("User-Agent:")
			if err != nil {
				return
			}
			reg_ac, err := regexp.Compile("Accept:")
			if err != nil {
				return
			}
			var new_buffer string
			new_buffer += line
			for err == nil {
				line, err = reader.ReadString('\n')
				if reg_host.MatchString(line) || reg_agent.MatchString(line) || reg_ac.MatchString(line) {
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