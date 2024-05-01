package rekorst

import (
	"encoding/hex"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/swag"
	"github.com/xiaokangwang/RekorSign/rekorapi/client"
	"github.com/xiaokangwang/RekorSign/rekorapi/client/entries"
	"github.com/xiaokangwang/RekorSign/rekorapi/models"
	"github.com/xiaokangwang/RekorSign/serial"
)

func NewRekoStLd(clientTransport runtime.ClientTransport) *RekoStLd {
	return &RekoStLd{
		api: client.New(clientTransport, nil),
	}
}

type RekoStLd struct {
	api *client.Rekor
}

func (r *RekoStLd) PutSHA512(hashValue string, pvk string) (string, error) {
	blobSerial := serial.X509SHA512{Sha512: hashValue}
	encoded, err := blobSerial.EncodeToSignature(pvk)
	if err != nil {
		return "", err
	}
	purposedEntry := &models.Hashedrekord{}
	purposedEntry.APIVersion = swag.String("0.0.1")
	var hashedRekordObj models.HashedrekordV001Schema
	hashedRekordObj.Data = &models.HashedrekordV001SchemaData{
		Hash: &models.HashedrekordV001SchemaDataHash{
			Algorithm: swag.String("sha512"),
			Value:     swag.String(hex.EncodeToString(encoded.Signed)),
		},
	}
	hashedRekordObj.Signature = &models.HashedrekordV001SchemaSignature{
		Content: encoded.Signature,
		PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
			Content: encoded.Certificate,
		},
	}

	purposedEntry.Spec = hashedRekordObj

	created, err := r.api.Entries.CreateLogEntry(&entries.CreateLogEntryParams{
		ProposedEntry: purposedEntry,
	})
	if err != nil {
		return "", err
	}
	var uuid string
	if created.Payload != nil {
		for k, _ := range created.Payload {
			uuid = k
		}
	}
	return uuid, nil
}
