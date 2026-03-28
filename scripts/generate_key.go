package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating random key: %v\n", err)
		os.Exit(1)
	}

	key := base64.StdEncoding.EncodeToString(b)
	fmt.Println(key)
}
