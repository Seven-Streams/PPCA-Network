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
		parsed := net.ParseIP(string(buffer[4:20]))
		host = string(parsed)
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
