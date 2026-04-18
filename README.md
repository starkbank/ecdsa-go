## A lightweight and fast pure Go ECDSA

### Overview

This is a pure Go implementation of the Elliptic Curve Digital Signature Algorithm. It is compatible with OpenSSL and uses elegant math such as Jacobian Coordinates to speed up the ECDSA on pure Go.

### Security

starkbank-ecdsa includes the following security features:

- **RFC 6979 deterministic nonces**: Eliminates the catastrophic risk of nonce reuse that leaks private keys
- **Low-S signature normalization**: Prevents signature malleability (BIP-62)
- **Public key on-curve validation**: Blocks invalid-curve attacks during verification
- **Montgomery ladder scalar multiplication**: Constant-operation variable-base point multiplication to mitigate timing side channels
- **Hash truncation**: Correctly handles hash functions larger than the curve order (e.g. SHA-512 with secp256k1)

### Installation

To install StarkBank's ECDSA-Go, run:

```sh
go get github.com/starkbank/ecdsa-go/v2
```

### Curves

We currently support `secp256k1` and `prime256v1` (P-256), but you can add more curves to the project. You just need to use the `curve.Add()` function.

### Speed

We ran a test on Go 1.26.2 on a MAC Pro. The libraries were run 100 times and the averages displayed below were obtained:

| Library            | sign           | verify   |
| ------------------ |:--------------:| --------:|
| starkbank/ecdsa-go |     0.7ms      |  1.1ms   |

Performance is driven by Jacobian coordinates, a Montgomery ladder for constant-time variable-base scalar multiplication, a precomputed window table (2^4-ary method) for the fixed generator used in signing, curve-specific shortcuts in point doubling (A=0 for secp256k1, A=-3 for prime256v1), Shamir's trick for combined scalar multiplication during verification, and the extended Euclidean algorithm for modular inversion.

### Sample Code

How to sign a json message for [Stark Bank]:

```go
package main

import (
	"fmt"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/ecdsa"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/privatekey"
)

func main() {
	// Generate privateKey from PEM string
	privateKey := privatekey.FromPem(`-----BEGIN EC PARAMETERS-----
BgUrgQQACg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIODvZuS34wFbt0X53+P5EnSj6tMjfVK01dD1dgDH02RzoAcGBSuBBAAK
oUQDQgAE/nvHu/SQQaos9TUljQsUuKI15Zr5SabPrbwtbfT/408rkVVzq8vAisbB
RmpeRREXj5aog/Mq8RrdYy75W9q/Ig==
-----END EC PRIVATE KEY-----`)

	message := `
    "transfers": [
        {
            "amount": 100000000,
            "taxId": "594.739.480-42",
            "name": "Daenerys Targaryen Stormborn",
            "bankCode": "341",
            "branchCode": "2201",
            "accountNumber": "76543-8",
            "tags": ["daenerys", "targaryen", "transfer-1-external-id"]
        }
    ]`

	signature := ecdsa.Sign(message, &privateKey)

	// Generate Signature in base64. This result can be sent to Stark Bank in the request header as the Digital-Signature parameter.
	fmt.Println(signature.ToBase64())

	// To double check if the message matches the signature, do this:
	publicKey := privateKey.PublicKey()

	fmt.Println(ecdsa.Verify(message, signature, &publicKey))
}

```

Simple use:

```go
package main

import (
	"fmt"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/curve"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/ecdsa"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/privatekey"
)

func main() {
	// Generate new Keys
	privateKey := privatekey.New(curve.Secp256k1)
	publicKey := privateKey.PublicKey()

	message := "My test message"

	// Generate Signature
	signature := ecdsa.Sign(message, &privateKey)
	fmt.Println(signature.ToBase64())

	// To verify if the signature is valid
	fmt.Println(ecdsa.Verify(message, signature, &publicKey))
}

```

How to add more curves:

```go
package main

import (
	"fmt"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/curve"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/publickey"
)

func main() {
	newCurve := curve.New(
		"frp256v1",
		"0xf1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c00",
		"0xee353fca5428a9300d4aba754a44c00fdfec0c9ae4b1a1803075ed967b7bb73f",
		"0xf1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c03",
		"0xf1fd178c0b3ad58f10126de8ce42435b53dc67e140d2bf941ffdd459c6d655e1",
		"0xb6b3d4c356c139eb31183d4749d423958c27d2dcaf98b70164c97a2dd98f5cff",
		"0x6142e0f7c8b204911f9271f0f3ecef8c2701c307e8e4c9e183115a1554062cfb",
		[]int64{1, 2, 250, 1, 223, 101, 256, 1},
		"",
	)

	curve.Add(newCurve)

	publicKeyPem := `-----BEGIN PUBLIC KEY-----
MFswFQYHKoZIzj0CAQYKKoF6AYFfZYIAAQNCAATeEFFYiQL+HmDYTf+QDmvQmWGD
dRJPqLj11do8okvkSxq2lwB6Ct4aITMlCyg3f1msafc/ROSN/Vgj69bDhZK6
-----END PUBLIC KEY-----`

	publicKey := publickey.FromPem(publicKeyPem)

	fmt.Println(publicKey.ToPem())
}
```

How to generate compressed public key:

```go
package main

import (
	"fmt"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/curve"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/privatekey"
)

func main() {
	privateKey := privatekey.New(curve.Secp256k1)
	publicKey := privateKey.PublicKey()
	compressedPublicKey := publicKey.ToCompressed()

	fmt.Println(compressedPublicKey)
}
```

How to recover a compressed public key:

```go
package main

import (
	"fmt"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/publickey"
)

func main() {
	compressedPublicKey := "0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2"
	pubKey := publickey.FromCompressed(compressedPublicKey)

	fmt.Println(pubKey.ToPem())
}
```

### OpenSSL

This library is compatible with OpenSSL, so you can use it to generate keys:

```
openssl ecparam -name secp256k1 -genkey -out privateKey.pem
openssl ec -in privateKey.pem -pubout -out publicKey.pem
```

Create a message.txt file and sign it:

```
openssl dgst -sha256 -sign privateKey.pem -out signatureDer.txt message.txt
```

To verify, do this:

```go
package main

import (
	"fmt"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/ecdsa"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/publickey"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/signature"
	"os"
)

func main() {
	publicKeyPem, _ := os.ReadFile("publicKey.pem")
	signatureDer, _ := os.ReadFile("signatureDer.txt")
	message, _ := os.ReadFile("message.txt")

	publicKey := publickey.FromPem(string(publicKeyPem))
	signature := signature.FromDer(signatureDer)

	fmt.Println(ecdsa.Verify(string(message), signature, &publicKey))
}

```

You can also verify it on terminal:

```
openssl dgst -sha256 -verify publicKey.pem -signature signatureDer.txt message.txt
```

NOTE: If you want to create a Digital Signature to use with [Stark Bank], you need to convert the binary signature to base64.

```
openssl base64 -in signatureDer.txt -out signatureBase64.txt
```

You can do the same with this library:

```go
package main

import (
	"fmt"
	"github.com/starkbank/ecdsa-go/v2/ellipticcurve/signature"
	"os"
)

func main() {
	signatureDer, _ := os.ReadFile("signatureDer.txt")

	signature := signature.FromDer(signatureDer)

	fmt.Println(signature.ToBase64())
}

```

### Run unit tests

```
cd tests && go test -v -count=1 ./...
```

### Run benchmark

```
cd tests && go test -bench=. -benchmem
```

[Stark Bank]: https://starkbank.com
