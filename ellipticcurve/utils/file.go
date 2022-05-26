package utils

import (
	"io/ioutil"
	"log"
)

type Filer interface {
	Read(path string) []byte
}

type File struct{}

func (obj File) Read(path string) []byte {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}

	return content
}
