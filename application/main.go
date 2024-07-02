package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

func HandleConnectionProxy(conn net.Conn) {
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
		parsed := net.ParseIP(string(buffer[4:20]))
		host = string(parsed)
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
	go io.Copy(new_conn, conn)
	io.Copy(conn, new_conn)
}

func proxy() {
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
		go HandleConnectionProxy(conn)
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()
	remote_conn, err := net.Dial("tcp", "localhost:24625") //dial to the server.
	if err != nil {
		return
	}
	defer remote_conn.Close()
	go io.Copy(remote_conn, conn)
	io.Copy(conn, remote_conn)
}

func Client() {
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

func parseHTTPRequest(request string) (host string) {
	reader := bufio.NewReader(strings.NewReader(request))
	_, _ = reader.ReadString('\n')
	for {
		line, err := reader.ReadString('\n')
		if err != nil || strings.TrimSpace(line) == "" {
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

func handleClientHttp(conn net.Conn) {
	whitelist := "../white_http.txt"
	blacklist := "../black_http.txt"
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
	host := parseHTTPRequest(string(buffer[:n]))
	if err != nil {
		return
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

func ClientHttp() {
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
		go handleClientHttp(conn)
	}
}

func handleClientIp(conn net.Conn) {
	whitelist := "../white_ip.txt"
	blacklist := "../black_ip.txt"
	defer conn.Close()
	remote_conn, err := net.Dial("tcp", "127.0.0.1:24625") //dial to the server.
	if err != nil {
		return
	}
	buffer := make([]byte, 1024)
	remote_buffer := make([]byte, 1024)
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
				defer remote_conn.Close()
				go io.Copy(remote_conn, conn)
				io.Copy(conn, remote_conn)
				return
			}
		}
	}
	remote_conn.Write(buffer[:n])
	defer remote_conn.Close()
	go io.Copy(remote_conn, conn)
	io.Copy(conn, remote_conn)
}

func ClientIp() {
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
		go handleClientIp(conn)
	}
}

func handleClientPid(conn net.Conn) {
	whitelist := "../white_pid.txt"
	blacklist := "../black_pid.txt"
	from := conn.RemoteAddr().String()
	parts := strings.Split(from, ":")
	port := parts[len(parts)-1]
	cmd := exec.Command("lsof", "-i", ":"+port)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return
	}
	output := out.String()
	reader := bufio.NewReader(strings.NewReader(output))
	_, err = reader.ReadString('\n')
	if err != nil {
		return
	}
	command_line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	slices := strings.Fields(command_line)
	name := slices[0]
	println(name)
	defer conn.Close()
	remote_conn, err := net.Dial("tcp", "127.0.0.1:24625") //dial to the server.
	if err != nil {
		return
	}
	buffer := make([]byte, 1024)
	remote_buffer := make([]byte, 1024)
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
			if expr.MatchString(name) {
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
			if expr.MatchString(name) {
				remote_conn.Close()
				port := int(buffer[n-2])<<8 | int(buffer[n-1])

				remote_conn, err = net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
				if err != nil {
					return
				}
				defer remote_conn.Close()
				go io.Copy(remote_conn, conn)
				io.Copy(conn, remote_conn)
				return
			}
		}
	}
	remote_conn.Write(buffer[:n])
	defer remote_conn.Close()
	go io.Copy(remote_conn, conn)
	io.Copy(conn, remote_conn)
}

func ClientPid() {
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
		go handleClientPid(conn)
	}
}

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

func fileExists(filename string) bool {
	file, err := os.Open(filename)
	if os.IsNotExist(err) {
		return false
	}
	defer file.Close()
	return err == nil
}

func handleClientTls(conn net.Conn) {
	whitelist := "../white_tls.txt"
	blacklist := "../black_tls.txt"
	defer conn.Close()
	remote_conn, err := net.Dial("tcp", "localhost:24625") //dial to the server.
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
	host := parseHTTPSRequest(buffer[:n])
	if err != nil {
		return
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

func ClientTls() {
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
