package main

import (
	"fmt"
	"os"
)

func main() {
	listenAddr, username, password := parseArgs(os.Args)

	fmt.Printf("listening socks5://%s\n", listenAddr)
	if err := NewServer(listenAddr, username, password).ListenAndServe(); err != nil {
		fmt.Println("[error]", err)
		os.Exit(1)
	}
}

func parseArgs(args []string) (string, string, string) {
	listenAddr := ":1080"
	username := ""
	password := ""

	switch len(args) {
	case 1:
	case 2:
		listenAddr = args[1]
	case 3:
		listenAddr = args[1]
		username = args[2]
	case 4:
		listenAddr = args[1]
		username = args[2]
		password = args[3]
	default:
		fmt.Println("socks5d [listenAddr] [username] [password]")
		os.Exit(0)
	}

	return listenAddr, username, password
}
