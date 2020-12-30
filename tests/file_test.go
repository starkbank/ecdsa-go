package tests

import (
	"testing"
	"../elipticcurve/utils"
)

func TestReadFile(t *testing.T) {
	content := utils.File{}.Read("./curve_test.go")

	if len(content) == 0 {
		t.Error("Error on reading file")
	}
}
