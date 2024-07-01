package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"runtime"
	"strings"
)

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

func fileExists(filename string) bool {
	file, err := os.Open(filename)
	if os.IsNotExist(err) {
		return false
	}
	defer file.Close()
	return err == nil
}

func handleClient(conn net.Conn) {
	server1 := "../server1.txt"
	server2 := "../server2.txt"
	defer conn.Close()
	buffer := make([]byte, 10240)
	n, err := conn.Read(buffer)
	if err != nil {
		return
	}
	host := parseHTTPRequest(string(buffer[:n]))
	if fileExists(server1) {
		file, err := os.Open(server1)
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
				new_conn, err := net.Dial("tcp", "127.0.0.1:22471")
				if err != nil {
					return
				}
				defer new_conn.Close()
				new_conn.Write(buffer[:n])
				go io.Copy(conn, new_conn)
				io.Copy(new_conn, conn)
			}
		}
		return
	}
	if fileExists(server2) {
		file, err := os.Open(server2)
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
				new_conn, err := net.Dial("tcp", "127.0.0.1:22471")
				if err != nil {
					return
				}
				defer new_conn.Close()
				new_conn.Write(buffer[:n])
				go io.Copy(conn, new_conn)
				io.Copy(new_conn, conn)
			}
		}
		return
	}
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	ln, err := net.Listen("tcp", ":24625") //listen on port 24625
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
