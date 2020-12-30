package tests

import (
	"testing"
	"../elipticcurve/utils"
)

func TestBase64(t *testing.T) {
	str := "tony stark"
	
	encoded := utils.Base64{}.Encode(str)
	decoded := utils.Base64{}.Decode(encoded)

	if decoded != str {
		t.Error("Encoding/Decoding gone wrong")
	}
}
