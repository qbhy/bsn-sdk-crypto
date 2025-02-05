package sm

import (
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/tjfoc/gmsm/sm2"
	"testing"
)

func TestSm2Handle_Sign(t *testing.T) {
	//	puk := `-----BEGIN PUBLIC KEY-----
	//MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEDW9srwJ97PuwNTXKpCBLz+Kgp8Bo
	//KS/i2zlbzA3gnrZPKjh8jfh++exUmliaJ1qlzeNeXHyEbV31Rqk4+Go3Tw==
	//-----END PUBLIC KEY-----`

	prik := `……`

	sm, err := NewSM2Handle("", prik)

	if err != nil {
		fmt.Println(err)
	}

	data := []byte("123456")

	si, _ := sm.Sign(data)

	b, err := sm.Verify(si, data)

	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(b)
}

func TestEncrypt(t *testing.T) {

	puk := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAECBTmBCyjjyg0h4F1f/PiLVNJyDM1
YRgctLay3FE5wWLqG0OH0p5fP8I5UT+pb1gkirIchlDxuwdVdVlUuQMrTQ==
-----END PUBLIC KEY-----`

	prik := `……`

	sm, err := NewSM2Handle(puk, prik)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("abc")

	cr, err := sm.Encrypt(data)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Encrypt：", hex.EncodeToString(cr))

	data, err = sm.Decrypt(cr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Decrypt：", string(data))

}

func TestGenerateKey(t *testing.T) {

	key, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	privateKey, err := sm2.WritePrivateKeytoMem(key, nil)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(string(privateKey))
	fmt.Println(hexutil.Encode(key.D.Bytes()))

	publicKey, err := sm2.WritePublicKeytoMem(&key.PublicKey, nil)

	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(string(publicKey))
}
