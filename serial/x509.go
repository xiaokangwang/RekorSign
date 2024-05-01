package serial

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
)

func CreateTopicKeyPair() (string, string, error) {
	pvk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	pub, err := x509.MarshalPKIXPublicKey(&pvk.PublicKey)
	if err != nil {
		return "", "", err
	}

	pubEncoded := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})

	pvkbytes, err := x509.MarshalECPrivateKey(pvk)
	if err != nil {
		return "", "", err
	}
	b64pvkbytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: pvkbytes})
	return string(pubEncoded), string(b64pvkbytes), nil
}

type X509SHA512 struct {
	Sha512 string
}

type X509SHA512Encoded struct {
	Certificate []byte
	Signed      []byte
	Signature   []byte
}

var ErrNoPEMBlock = errors.New("no PEM block found")

func (b *X509SHA512) EncodeToSignature(pvk string) (*X509SHA512Encoded, error) {
	block, _ := pem.Decode([]byte(pvk))
	if block == nil {
		return nil, ErrNoPEMBlock
	}
	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pub, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}

	pubEncoded := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})

	var toBeSigned [64]byte

	hex.Decode(toBeSigned[:], []byte(b.Sha512))

	sig, err := ecdsa.SignASN1(rand.Reader, priv, toBeSigned[:])
	if err != nil {
		return nil, err
	}

	return &X509SHA512Encoded{
		Certificate: []byte(pubEncoded),
		Signed:      toBeSigned[:],
		Signature:   sig,
	}, nil
}
