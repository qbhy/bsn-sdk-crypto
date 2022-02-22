package secp256r1

import (
	"crypto/sha256"
	"encoding/base64"
)

// Signature 根据私钥生成签名，会 base64
func Signature(data []byte, privateKey string) (string, error) {
	var sign, signErr = SignatureRaw(data, privateKey)

	if signErr != nil {
		return "", signErr
	}

	return base64.StdEncoding.EncodeToString(sign), nil
}

// SignatureRaw 根据私钥生成签名，不包含 base64
func SignatureRaw(data []byte, privateKey string) ([]byte, error) {
	var pk, err = LoadPrivateKey(privateKey)

	if err != nil {
		return nil, err
	}

	var h = sha256.New()

	h.Write(data)
	var hash = h.Sum(nil)

	return SignECDSA(pk, hash)
}
