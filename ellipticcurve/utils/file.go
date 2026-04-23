package utils

import (
	"log"
	"os"
)

type File struct{}

func (obj File) Read(path string) []byte {
	content, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}

	return content
}
