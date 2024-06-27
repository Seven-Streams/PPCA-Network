package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"runtime"
)

func fileExists(filename string) bool {
	file, err := os.Open(filename)
	if os.IsNotExist(err) {
		return false
	}
	defer file.Close()
	return err == nil
}

func handleClient(conn net.Conn) {
	whitelist := "../white.txt"
	blacklist := "../black.txt"
	defer conn.Close()
	remote_conn, err := net.Dial("tcp", "127.0.0.1:24625") //dial to the server.
	if err != nil {
		return
	}
	buffer := make([]byte, 1024)
	remote_buffer := make([]byte, 1024)
	_, err = conn.Read(buffer) //the first pack.
	if err != nil {
		return
	}
	fmt.Println("OK1")
	_, err = remote_conn.Write(buffer) //pass the first pack.
	if err != nil {
		return
	}
	fmt.Println("OK2")
	_, err = remote_conn.Read(remote_buffer) //get the first reply.
	if err != nil {
		return
	}
	fmt.Println("OK3")
	_, err = conn.Write(remote_buffer) //pass the first reply.
	if err != nil {
		return
	}
	fmt.Println("OK4")
	n, err := conn.Read(buffer)
	fmt.Println("OK5")
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
				break
			}
		}
	}
	defer remote_conn.Close()
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