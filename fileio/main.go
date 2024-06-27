package main

import (
	"fmt"
	"os"
)

func main() {
	for {
		whitelist := "../white.txt"
		blacklist := "../black.txt"
		fmt.Println("Input 1 to set whitelist, Input 2 to set blacklist, Input other to quit.")
		var kind int
		var expr string
		fmt.Scanln(&kind)
		fmt.Scanln(&expr)
		expr += "\n"
		if kind == 1 {
			file, err := os.OpenFile(whitelist, os.O_RDWR|os.O_APPEND, 0666)
			if err != nil {
				panic(err)
			}
			file.Write([]byte(expr))
			file.Close()
		} else {
			if kind == 2 {
				file, err := os.OpenFile(blacklist, os.O_RDWR|os.O_APPEND, 0666)
				if err != nil {
					panic(err)
				}
				file.Write([]byte(expr))
				file.Close()
			} else {
				os.Exit(1)
			}
		}
	}
}
