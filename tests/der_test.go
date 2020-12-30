package tests

import (
	"testing"
	. "../elipticcurve/utils"
)

func TestEncodeSequence(t *testing.T) {
	str := "tony stark"
	
	ans := Der{}.EncodeSequence([]byte(str))

	if ans == nil {
		t.Error("Sequence encoding gone wrong")
	}
}

func TestEncodeLength(t *testing.T) {
	val := 64
	
	ans := Der{}.EncodeLength(val)

	if ans == nil {
		t.Error("Length encoding gone wrong")
	}
}
