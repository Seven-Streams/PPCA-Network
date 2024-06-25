package proxy

import (
	"net"
	"runtime"
)

func handleConnection(conn net.Conn) {
	defer conn.Close()
	res, err := net.Dial("tcp")
}

func main() {
	runtime.GOMAXPROCS(2)
	ln, err := net.Listen("tcp", ":24625")
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
