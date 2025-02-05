package secp256k1

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/pem"
	"math/big"

	"github.com/BSNDA/bsn-sdk-crypto/errors"
)

const (
	PublicKeyType = "PUBLIC KEY"
	CertType      = "CERTIFICATE"
)

func getPuk(pub string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pub))

	if block == nil {
		return nil, errors.New("load public key failed")
	}

	if block.Type == PublicKeyType {

		return LoadPublicKey([]byte(pub))
	}

	if block.Type == CertType {
		return LoadPublicKeyByCert([]byte(pub))

	}

	return nil, errors.New("cert loading failed")
}

func NewEcdsaK1Handle(pub, pri string) (*ecdsaK1Handle, error) {
	priKey, err := LoadPrivateKey([]byte(pri))

	if err != nil {
		return nil, errors.New("cert loading failed")
	}

	var pubKey *ecdsa.PublicKey
	if pub == "" {
		pubKey = &priKey.PublicKey
	} else {
		pubKey, err = getPuk(pub)
		if err != nil {
			return nil, errors.New("cert loading failed")
		}
	}

	ecdsa := &ecdsaK1Handle{
		pubKey: pubKey,
		priKey: priKey,
	}

	return ecdsa, nil
}

type ecdsaK1Handle struct {
	pubKey *ecdsa.PublicKey
	priKey *ecdsa.PrivateKey
}

func (e *ecdsaK1Handle) Hash(msg []byte) ([]byte, error) {

	h := sha256.New()

	h.Write([]byte(msg))
	hash := h.Sum(nil)

	return hash, nil
}

func (e *ecdsaK1Handle) Sign(digest []byte) ([]byte, error) {
	return SignECDSA(e.priKey, digest)

}

func (e *ecdsaK1Handle) Verify(sign, digest []byte) (bool, error) {
	return VerifyECDSA(e.pubKey, sign, digest)

}

func NewKey(k *big.Int) (*ecdsa.PrivateKey, error) {
	secp256k1 := SECP256K1()
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = secp256k1
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = secp256k1.ScalarBaseMult(k.Bytes())
	return priv, nil
}
