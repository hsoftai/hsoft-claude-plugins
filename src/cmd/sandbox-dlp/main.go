package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		runServe()
	case "status":
		runStatus()
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "sandbox-dlp — per-user secret-rendering file provider")
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  sandbox-dlp serve    run the control service (per-user)")
	fmt.Fprintln(os.Stderr, "  sandbox-dlp status   report whether the service is running")
}
