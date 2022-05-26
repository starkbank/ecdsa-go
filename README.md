# ecdsa-go
## A lightweight and fast pure Go ECDSA library

### Overview

This is a pure Golang implementation of the Elliptic Curve Digital Signature Algorithm. It is compatible with OpenSSL and uses elegant math such as Jacobian Coordinates to speed up the ECDSA on pure Golang.

### Installation

To install StarkBank`s ECDSA-Go, run:

```sh
go get github.com/starkbank/ecdsa-go
```

### Curves

We currently support `secp256k1`, but it's super easy to add more curves to the project. Just add them on `curve.go`

### Speed

We ran a test on a Macbook Pro M1 2020. The libraries were run 100 times and the averages displayed bellow were obtained:

| Library            | sign           | verify   |
| ------------------ |:--------------:| --------:|
| starkbank/ecdsa-go |     1.40ms     |  2.90ms  |

### Sample Code

How to sign a json message for [Stark Bank]:

```go
package main

import (
	"fmt"
	"github.com/starkbank/ecdsa-go/ellipticcurve/ecdsa"
	"github.com/starkbank/ecdsa-go/ellipticcurve/privatekey"
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
	"math/big"
	"github.com/starkbank/ecdsa-go/ellipticcurve/curve"
	"github.com/starkbank/ecdsa-go/ellipticcurve/ecdsa"
	"github.com/starkbank/ecdsa-go/ellipticcurve/privatekey"
)

func main() {
  	// Generate new Keys
	privateKey := privatekey.New(curve.secp256k1)
	publicKey := privateKey.PublicKey()

	message := "My test message"

  	// Generate Signature
	signer := ecdsa.Sign(message, &privateKey)
	fmt.Println(signer.ToBase64())

  	// To verify if the signature is valid
	verifer := ecdsa.Verify(message, signer, &publicKey)
	fmt.Println(verifer)
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
	"os"
	"github.com/starkbank/ecdsa-go/ellipticcurve/ecdsa"
	"github.com/starkbank/ecdsa-go/ellipticcurve/publickey"
	"github.com/starkbank/ecdsa-go/ellipticcurve/signature"
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
	"os"
	"github.com/starkbank/ecdsa-go/ellipticcurve/signature"
)

func main() {
	signatureDer, _ := os.ReadFile("signatureDer.txt")

	signature := signature.FromDer(signatureDer)

	fmt.Println(signature.ToBase64())
}
```

[Stark Bank]: https://starkbank.com
