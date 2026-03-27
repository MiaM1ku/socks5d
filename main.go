package main

import (
	"fmt"
	"os"
)

func main() {
	listenAddr, username, password := parseArgs(os.Args)

	fmt.Printf("Listening SOCKS5 on %s\n", listenAddr)
	if username != "" {
		fmt.Printf("Authentication enabled for user: %s\n", username)
	} else {
		fmt.Println("No authentication required")
	}

	server := NewServer(listenAddr, username, password)
	if err := server.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Server failed: %v\n", err)
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
		fmt.Printf("Usage: %s [listenAddr] [username] [password]\n", args[0])
		fmt.Printf("Example: %s :1080 admin 123456\n", args[0])
		os.Exit(0)
	}

	return listenAddr, username, password
}