package keystore

import (
	"crypto"
	"github.com/qbhy/bsn-sdk-crypto/errors"
	"github.com/qbhy/bsn-sdk-crypto/keystore/key"
)

func BCCSPKeyRequestGenerate(ks key.KeyStore, keyOpts key.KeyGenOpts) (key.Key, crypto.Signer, error) {

	key, err := KeyGen(keyOpts)
	if err != nil {
		return nil, nil, err
	}

	ks.StoreKey(key)

	cspSigner, err := New(key)
	if err != nil {
		return nil, nil, errors.New("Failed initializing CryptoSigner")
	}
	return key, cspSigner, nil
}
