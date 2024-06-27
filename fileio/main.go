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
		if kind == 1 {
			fmt.Scanln(&expr)
			expr += "\n"
			file, err := os.OpenFile(whitelist, os.O_CREATE|os.O_APPEND, 0666)
			if err != nil {
				panic(err)
			}
			file.Write([]byte(expr))
			file.Close()
		} else {
			if kind == 2 {
				fmt.Scanln(&expr)
				expr += "\n"
				file, err := os.OpenFile(blacklist, os.O_CREATE|os.O_APPEND, 0666)
				if err != nil {
					panic(err)
				}
				file.Write([]byte(expr))
				file.Close()
			} else {
				fmt.Println("bye")
				os.Exit(1)
			}
		}
	}
}
