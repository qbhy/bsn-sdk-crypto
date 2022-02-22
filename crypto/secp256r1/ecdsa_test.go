package secp256r1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"

	"github.com/qbhy/bsn-sdk-crypto/utils"
)

func TestNewPuk(t *testing.T) {

	curve := elliptic.P256()
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)

	if err != nil {
		t.Fatal(err)
	}

	rawKey, _ := utils.PrivateKeyToPEM(privKey, nil)

	fmt.Println(string(rawKey))

	puk, _ := utils.PublicKeyToPEM(privKey.Public(), nil)

	fmt.Println(string(puk))

	data := []byte("123456")

	fmt.Println(string(data))

	h := sha256.New()

	h.Write(data)
	hash := h.Sum(nil)

	prk, _ := LoadPrivateKey(string(rawKey))

	sign, _ := SignECDSA(prk, hash)

	fmt.Println(base64.StdEncoding.EncodeToString(sign))

}

func TestSignature(t *testing.T) {

	puk := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEy4wBr/o5jSJHopiBfe9rhPhn//y
+Qf35AH4wwa92AjxLuhk28GlzOK7YiB5BitgttSlk+wLgTlEPF9m18cAvw==
-----END PUBLIC KEY-----`

	priker := `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgxjJR06JfqaHDcpIN
JQb+MH0Bs2nWIhRUFJ3P4fIA8kCgCgYIKoZIzj0DAQehRANCAATko6mtCruC7pLI
MOZ4ktl9J2Lg5uQKx4fLIqT2oSZiFsZRhoMnaKmUfAPcYy3zaVmTtRkddHnTi0EC
V/xD6Mpe
-----END PRIVATE KEY-----`

	var ec, err = NewEcdsaR1Handle(puk, priker)

	if err != nil {
		fmt.Println(err)
		assert.Nil(t, err, err)
	}

	var (
		data = []byte("bsn")

		sign, sianErr = SignatureRaw(data, priker)
	)

	assert.Nil(t, sianErr, sianErr)

	var _, verifyErr = ec.Verify(sign, data)

	assert.Nil(t, verifyErr, verifyErr)

	fmt.Println(sign)
}
