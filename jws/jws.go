package jws

import (
	"bytes"
	"compress/gzip"
	"gopkg.in/square/go-jose.v2"
)

type Module struct{}

func New() *Module {
	return &Module{}
}
func (m *Module) Sign(key *jose.JSONWebKey, payload string, sigAlg jose.SignatureAlgorithm) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: sigAlg, Key: key}, nil)
	if err != nil {
		return "", err
	}
	obj, err := signer.Sign([]byte(payload))
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()

}

func (m *Module) GzipAndSign(key *jose.JSONWebKey, payload string, sigAlg jose.SignatureAlgorithm) (string, error) {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write([]byte(payload)); err != nil {
		return "", err
	}
	if err := gz.Close(); err != nil {
		return "", err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: sigAlg, Key: key}, nil)
	if err != nil {
		return "", err
	}
	obj, err := signer.Sign(b.Bytes())
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

func (m *Module) Verify(key *jose.JSONWebKey, jws string) (string, error) {
	obj, err := jose.ParseSigned(jws)
	if err != nil {
		return "", err
	}
	plaintextBytes, err := obj.Verify(key)
	return string(plaintextBytes), err
}

func (m *Module) VerifyGzipped(key *jose.JSONWebKey, jws string) (string, error) {
	obj, err := jose.ParseSigned(jws)
	if err != nil {
		return "", err
	}
	plaintextBytes, err := obj.Verify(key)
	if err != nil {
		return "", err
	}
	reader, err := gzip.NewReader(bytes.NewReader(plaintextBytes))
	defer reader.Close()
	buf := &bytes.Buffer{}
	_, err = buf.ReadFrom(reader)
	if err != nil {
		return "", err
	}
	return buf.String(), err
}
