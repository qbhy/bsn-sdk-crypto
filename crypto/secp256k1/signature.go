package secp256k1

import (
	"encoding/base64"
)

// Signature 根据私钥生成签名，会 base64
func Signature(data, privateKey []byte) (string, error) {
	var sign, signErr = SignatureRaw(data, privateKey)
	if signErr != nil {
		return "", signErr
	}

	return base64.StdEncoding.EncodeToString(sign), nil
}

// SignatureRaw 根据私钥生成签名，不包含 base64
func SignatureRaw(data, privateKey []byte) ([]byte, error) {
	var pk, err = LoadPrivateKey(privateKey)

	if err != nil {
		return nil, err
	}

	var (
		ecdsa = &ecdsaK1Handle{pubKey: &pk.PublicKey, priKey: pk}

		dis, hashErr = ecdsa.Hash(data)
	)

	if hashErr != nil {
		return nil, hashErr
	}

	return ecdsa.Sign(dis)
}
