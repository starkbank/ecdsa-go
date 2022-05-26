package utils

import (
	"fmt"
	"math/big"
	"strings"
	"time"
)

const (
	Integer                 = "integer"
	BitString               = "bitString"
	OctetString             = "octetString"
	Null                    = "null"
	Object                  = "object"
	PrintableString         = "printableString"
	UtcTime                 = "utcTime"
	Sequence                = "sequence"
	Set                     = "set"
	OidContainer            = "oidContainer"
	PublicKeyPointContainer = "publicKeyPointContainer"
)

var hexTagtoType = map[string]string{
	"02": Integer,
	"03": BitString,
	"04": OctetString,
	"05": Null,
	"06": Object,
	"13": PrintableString,
	"17": UtcTime,
	"30": Sequence,
	"31": Set,
	"a0": OidContainer,
	"a1": PublicKeyPointContainer,
}

var typeToHexTag = ReverseMap(hexTagtoType)

func EncodeConstructed(encodedValues ...string) string {
	return EncodePrimitive(Sequence, strings.Join(encodedValues, ""))
}

func EncodePrimitive(tagType string, value interface{}) string {
	if tagType == Integer {
		value = EncodeInteger(value.(*big.Int))
	}
	if tagType == Object {
		value = OidToHex(value.([]int64))
	}
	return fmt.Sprintf("%s%s%s", typeToHexTag[tagType], GenerateLengthBytes(value.(string)), value)
}

func Parse(hexadecimal string) []interface{} {
	if hexadecimal == "" {
		return []interface{}{}
	}
	typeByte := hexadecimal[:2]
	hexadecimal = hexadecimal[2:]
	length, lengthBytes := ReadLengthBytes(hexadecimal)
	content := hexadecimal[lengthBytes : lengthBytes+length]
	hexadecimal = hexadecimal[lengthBytes+length:]
	if len(content) < length {
		panic("missing bytes in DER parse")
	}

	tagData := GetTagData(typeByte)
	if tagData["isConstructed"].(bool) {
		nextContent := Parse(hexadecimal)
		if len(nextContent) == 0 {
			return []interface{}{Parse(content)}
		}
		return append([]interface{}{Parse(content)}, nextContent[0])
	}

	var contentArray []interface{}
	switch tagData["type"] {
	case Null:
		contentArray = []interface{}{ParseNull(content)}
	case Object:
		contentArray = []interface{}{ParseOid(content)}
	case UtcTime:
		contentArray = []interface{}{ParseTime(content)}
	case Integer:
		contentArray = []interface{}{ParseInteger(content)}
	case PrintableString:
		contentArray = []interface{}{ParseString(content)}
	default:
		contentArray = []interface{}{ParseAny(content)}
	}
	return append(contentArray, Parse(hexadecimal)...)
}

func ParseAny(hexadecimal string) string {
	return hexadecimal
}

func ParseOid(hexadecimal string) []int64 {
	return OidFromHex(hexadecimal)
}

func ParseTime(hexadecimal string) time.Time {
	parsedHex := ParseString(hexadecimal)
	layout := "060102150405"
	parsedTime, _ := time.Parse(layout, parsedHex)
	return parsedTime
}

func ParseString(hexadecimal string) string {
	return string(ByteStringFromHex(hexadecimal)[:])
}

func ParseNull(content string) string {
	return ""
}

func ParseInteger(hexadecimal string) *big.Int {
	integer := IntFromHex(hexadecimal)
	bits := BitsFromHex(hexadecimal[0:1])
	if bits[0:1] == "0" { // negative numbers are encoded using two's complement
		return integer
	}
	bitCount := 4 * len(hexadecimal)
	return integer.Sub(integer, new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(bitCount)), nil))
}

func EncodeInteger(number *big.Int) string {
	hexadecimal := HexFromInt(big.NewInt(0).Abs(number))
	if number.Cmp(big.NewInt(0)) < 0 {
		bitCount, twosComplement := new(big.Int), new(big.Int)
		bitCount = big.NewInt(int64(4 * len(hexadecimal)))
		twosComplement.Exp(big.NewInt(2), bitCount, nil).Add(twosComplement, number)
		return HexFromInt(twosComplement)
	}
	bits := BitsFromHex(string(hexadecimal[0]))
	if string(bits[0]) == "1" { // if first bit was left as 1, number would be parsed as a negative integer with two's complement
		hexadecimal = "00" + hexadecimal
	}
	return hexadecimal
}

func ReadLengthBytes(hexadecimal string) (int, int) {
	lengthBytes := 2

	lengthIndicator := int(IntFromHex(hexadecimal).Uint64())
	if len(hexadecimal) > 2 {
		lengthIndicator = int(IntFromHex(hexadecimal[0:lengthBytes]).Uint64())
	}
	isShortForm := lengthIndicator < 128 // checks if first bit of byte is 1 (a.k.a. short-form)
	if isShortForm {
		length := lengthIndicator * 2
		return length, lengthBytes
	}
	lengthLength := lengthIndicator - 128 // nullifies first bit of byte (only used as long-form flag)
	if lengthLength == 0 {
		panic("indefinite length encoding located in DER")
	}
	lengthBytes += 2 * lengthLength
	length := int(IntFromHex(hexadecimal[2:lengthBytes]).Uint64()) * 2
	return length, lengthBytes
}

func GenerateLengthBytes(hexadecimal string) string {
	size := len(hexadecimal) / 2
	length := HexFromInt(big.NewInt(int64(size)))
	if size < 128 { // checks if first bit of byte should be 0 (a.k.a. short-form flag)
		return fmt.Sprintf("%02s", length)
	}
	lengthLength := 128 + len(length)/2 // +128 sets the first bit of the byte as 1 (a.k.a. long-form flag)
	return HexFromInt(big.NewInt(int64(lengthLength))) + length
}

func GetTagData(tag string) map[string]interface{} {
	bits := BitsFromHex(tag)[:3]
	bit8, bit7, bit6 := string(bits[0]), string(bits[1]), string(bits[2])

	var tagClass string
	switch bit8 {
	case "0":
		tagClass = "universal"
		if bit7 == "1" {
			tagClass = "application"
		}
	case "1":
		tagClass = "context-specific"
		if bit7 == "1" {
			tagClass = "private"
		}
	default:
		tagClass = ""
	}

	isConstructed := bit6 == "1"
	tagType := hexTagtoType[tag]
	if tagType == "" {
		tagType = ""
	}

	return map[string]interface{}{
		"class":         tagClass,
		"isConstructed": isConstructed,
		"type":          tagType,
	}
}
