package sm

import (
	"encoding/pem"
	"math/big"

	"github.com/BSNDA/bsn-sdk-crypto/errors"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
)

const (
	PublicKeyType = "PUBLIC KEY"
	CertType      = "CERTIFICATE"
)

var (
	default_uid = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
)

func RedPublicKeyByPEM(pub string) (*sm2.PublicKey, error) {
	block, _ := pem.Decode([]byte(pub))

	if block == nil {
		return nil, errors.New("not pem")
	}
	if block.Type == PublicKeyType {
		return sm2.ReadPublicKeyFromMem([]byte(pub), nil)
	}

	if block.Type == CertType {
		x509Cert, err := sm2.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return sm2.ParseSm2PublicKey(x509Cert.RawSubjectPublicKeyInfo)
	}
	return nil, errors.New("Error")
}

func NewSM2Handle(pub, pri string) (*sm2Handle, error) {

	priKey, err := sm2.ReadPrivateKeyFromMem([]byte(pri), nil)

	if err != nil {
		return nil, errors.New("load private key has error")
	}

	var pubKey *sm2.PublicKey

	if pub == "" {
		pubKey = &priKey.PublicKey
	} else {
		pubKey, err = RedPublicKeyByPEM(pub)
		if err != nil {
			return nil, errors.New("load public key has error")
		}
	}
	ecdsa := &sm2Handle{
		pubKey: pubKey,
		priKey: priKey,
	}

	return ecdsa, nil
}

func NewTransUserSMHandle(priKey *sm2.PrivateKey) *sm2Handle {

	ecdsa := &sm2Handle{
		pubKey: &priKey.PublicKey,
		priKey: priKey,
	}

	return ecdsa
}

type sm2Handle struct {
	pubKey *sm2.PublicKey
	priKey *sm2.PrivateKey
}

func (e *sm2Handle) Hash(msg []byte) ([]byte, error) {

	h := sm3.New()

	h.Write([]byte(msg))
	hash := h.Sum(nil)

	return hash, nil
}

func (e *sm2Handle) Sign(digest []byte) ([]byte, error) {
	r, s, err := sm2.Sm2Sign(e.priKey, digest, default_uid)

	sign, err := sm2.SignDigitToSignData(r, s)
	if err != nil {
		return nil, err
	}

	return sign, nil

}

func (e *sm2Handle) Verify(sign, digest []byte) (bool, error) {

	r, s, _ := sm2.SignDataToSignDigit(sign)

	v := sm2.Sm2Verify(e.pubKey, digest, default_uid, r, s)

	return v, nil
}

func (e *sm2Handle) Encrypt(data []byte) ([]byte, error) {

	return sm2.Encrypt(e.pubKey, data)

}

func (e *sm2Handle) Decrypt(data []byte) ([]byte, error) {

	return sm2.Decrypt(e.priKey, data)

}

func NewKey(k *big.Int) (*sm2.PrivateKey, error) {
	secp256k1 := sm2.P256Sm2()
	priv := new(sm2.PrivateKey)
	priv.PublicKey.Curve = secp256k1
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = secp256k1.ScalarBaseMult(k.Bytes())
	return priv, nil
}
