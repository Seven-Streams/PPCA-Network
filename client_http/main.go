package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"runtime"
	"strings"
)

func parseHTTPSRequest(stream []byte) (host string) {
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

func parseHTTPRequest(request string) (host string, err error) {
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
	host, err := parseHTTPRequest(string(buffer[:n]))
	if err != nil {
		host = parseHTTPSRequest(buffer[:n])
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
