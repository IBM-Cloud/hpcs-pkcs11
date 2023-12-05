package main

import (
	"testing"
)

func TestCSRGen(t *testing.T) {
	p, session, err := PKCS11Init()
	if err != nil {
		panic(err)
	}
	defer PKCS11Destroy(p, session)

	curves := []string{"P-224", "P-256", "P-384", "P-521", "ED25519", "RSA"}

	for _, curve := range curves {
		hpcsPrivateKey := GenerateHPCSKeyPair(p, session, curve, nil, nil)
		_, err = generateCSR(hpcsPrivateKey, curve)
		if err != nil {
			t.Errorf("Error generating CSR: %v", err)
			return
		}
	}
}
