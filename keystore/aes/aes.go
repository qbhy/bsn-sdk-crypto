package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/BSNDA/bsn-sdk-crypto/keystore/key"
)

// GetRandomBytes returns len random looking bytes
func GetRandomBytes(len int) ([]byte, error) {
	if len < 0 {
		return nil, errors.New("Len must be larger than 0")
	}

	buffer := make([]byte, len)

	n, err := rand.Read(buffer)
	if err != nil {
		return nil, err
	}
	if n != len {
		return nil, fmt.Errorf("Buffer not filled. Requested [%d], got [%d]", len, n)
	}

	return buffer, nil
}

func pkcs7Padding(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func Pkcs7PaddingKey(src []byte) []byte {
	return pkcs7Padding(src)
}

func pkcs7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > aes.BlockSize || unpadding == 0 {
		return nil, errors.New("Invalid pkcs7 padding (unpadding > aes.BlockSize || unpadding == 0)")
	}

	pad := src[len(src)-unpadding:]
	for i := 0; i < unpadding; i++ {
		if pad[i] != byte(unpadding) {
			return nil, errors.New("Invalid pkcs7 padding (pad[i] != unpadding)")
		}
	}

	return src[:(length - unpadding)], nil
}

func aesCBCEncrypt(key, s []byte) ([]byte, error) {
	return aesCBCEncryptWithRand(rand.Reader, key, s)
}

func aesCBCEncryptWithRand(prng io.Reader, key, s []byte) ([]byte, error) {
	if len(s)%aes.BlockSize != 0 {
		return nil, errors.New("Invalid plaintext. It must be a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(s))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(prng, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], s)

	return ciphertext, nil
}

func aesCBCEncryptWithIV(IV []byte, key, s []byte) ([]byte, error) {
	if len(s)%aes.BlockSize != 0 {
		return nil, errors.New("Invalid plaintext. It must be a multiple of the block size")
	}

	if len(IV) != aes.BlockSize {
		return nil, errors.New("Invalid IV. It must have length the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(s))
	copy(ciphertext[:aes.BlockSize], IV)

	mode := cipher.NewCBCEncrypter(block, IV)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], s)

	return ciphertext, nil
}

func aesCBCDecrypt(key, src []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(src) < aes.BlockSize {
		return nil, errors.New("Invalid ciphertext. It must be a multiple of the block size")
	}
	iv := src[:aes.BlockSize]
	src = src[aes.BlockSize:]

	if len(src)%aes.BlockSize != 0 {
		return nil, errors.New("Invalid ciphertext. It must be a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(src, src)

	return src, nil
}

// AESCBCPKCS7Encrypt combines CBC encryption and PKCS7 padding
func AESCBCPKCS7Encrypt(key, src []byte) ([]byte, error) {
	// First pad
	tmp := pkcs7Padding(src)

	// Then encrypt
	return aesCBCEncrypt(key, tmp)
}

// AESCBCPKCS7Encrypt combines CBC encryption and PKCS7 padding using as prng the passed to the function
func AESCBCPKCS7EncryptWithRand(prng io.Reader, key, src []byte) ([]byte, error) {
	// First pad
	tmp := pkcs7Padding(src)

	// Then encrypt
	return aesCBCEncryptWithRand(prng, key, tmp)
}

// AESCBCPKCS7Encrypt combines CBC encryption and PKCS7 padding, the IV used is the one passed to the function
func AESCBCPKCS7EncryptWithIV(IV []byte, key, src []byte) ([]byte, error) {
	// First pad
	tmp := pkcs7Padding(src)

	// Then encrypt
	return aesCBCEncryptWithIV(IV, key, tmp)
}

// AESCBCPKCS7Decrypt combines CBC decryption and PKCS7 unpadding
func AESCBCPKCS7Decrypt(key, src []byte) ([]byte, error) {
	// First decrypt
	pt, err := aesCBCDecrypt(key, src)
	if err == nil {
		return pkcs7UnPadding(pt)
	}
	return nil, err
}

// AESCBCPKCS7ModeOpts contains options for AES encryption in CBC mode
// with PKCS7 padding.
// Notice that both IV and PRNG can be nil. In that case, the BCCSP implementation
// is supposed to sample the IV using a cryptographic secure PRNG.
// Notice also that either IV or PRNG can be different from nil.
type AESCBCPKCS7ModeOpts struct {
	// IV is the initialization vector to be used by the underlying cipher.
	// The length of IV must be the same as the Block's block size.
	// It is used only if different from nil.
	IV []byte
	// PRNG is an instance of a PRNG to be used by the underlying cipher.
	// It is used only if different from nil.
	PRNG io.Reader
}

type aescbcpkcs7Encryptor struct{}

func (e *aescbcpkcs7Encryptor) Encrypt(k key.Key, plaintext []byte, opts key.EncrypterOpts) ([]byte, error) {
	switch o := opts.(type) {
	case *AESCBCPKCS7ModeOpts:
		// AES in CBC mode with PKCS7 padding

		if len(o.IV) != 0 && o.PRNG != nil {
			return nil, errors.New("Invalid options. Either IV or PRNG should be different from nil, or both nil.")
		}

		if len(o.IV) != 0 {
			// Encrypt with the passed IV
			return AESCBCPKCS7EncryptWithIV(o.IV, k.(*aesPrivateKey).privKey, plaintext)
		} else if o.PRNG != nil {
			// Encrypt with PRNG
			return AESCBCPKCS7EncryptWithRand(o.PRNG, k.(*aesPrivateKey).privKey, plaintext)
		}
		// AES in CBC mode with PKCS7 padding
		return AESCBCPKCS7Encrypt(k.(*aesPrivateKey).privKey, plaintext)
	case AESCBCPKCS7ModeOpts:
		return e.Encrypt(k, plaintext, &o)
	default:
		return nil, fmt.Errorf("Mode not recognized [%s]", opts)
	}
}

type aescbcpkcs7Decryptor struct{}

func (*aescbcpkcs7Decryptor) Decrypt(k key.Key, ciphertext []byte, opts key.DecrypterOpts) ([]byte, error) {
	// check for mode
	switch opts.(type) {
	case *AESCBCPKCS7ModeOpts, AESCBCPKCS7ModeOpts:
		// AES in CBC mode with PKCS7 padding
		return AESCBCPKCS7Decrypt(k.(*aesPrivateKey).privKey, ciphertext)
	default:
		return nil, fmt.Errorf("Mode not recognized [%s]", opts)
	}
}
