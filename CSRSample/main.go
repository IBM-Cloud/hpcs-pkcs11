package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/miekg/pkcs11"
)

var NORMAL_APIKEY = ""

// library path
var PKCS11_LIBARY_PATH = "./grep11-pkcs11.so"

// KEY_TYPE valied options:
//  1. For ECDSA: "P-224", "P-256", "P-384", "P-521"
//  2. For EDDSA: "ED25519"
//  3. For RSA:   "RSA"
var KEY_TYPE = "RSA"

// EXISTING_KEY valied options:
// true  - Use existing key pair in HPCS instance for CSR generation
// false - Create new key pair for CSR generation
var EXISTING_KEY = false

// If EXISTING_KEY == true, the labels are used for load the existing key pair, then use the key pair for CSR generation.
// If EXISTING_KEY == false, the labels are used for generate the new key pair, then use the key pair for CSR generation.
var PUBLIC_CKA_LABEL = "csrrobintestrsa"
var PRIVATE_CKA_LABEL = "csrrobintestrsa"

// CSR Infomation
var CommonName = "RobinTEST"
var Country = "CN"
var Organization = "IBM"
var OrganizationalUnit = "CSL"
var Locality = "Beijing"
var Province = "Beijing"

type HPCSPrivateKey struct {
	P                *pkcs11.Ctx
	Session          pkcs11.SessionHandle
	PublicHandle     pkcs11.ObjectHandle
	PrivateHandle    pkcs11.ObjectHandle
	EncodedPublicKey []byte
	SignMech         uint
}

func (priv *HPCSPrivateKey) Public() crypto.PublicKey {
	pub, err := x509.ParsePKIXPublicKey(priv.EncodedPublicKey)
	if err != nil {
		panic(err)
	}
	return pub
}

func (priv *HPCSPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	err := priv.P.SignInit(priv.Session, []*pkcs11.Mechanism{pkcs11.NewMechanism(priv.SignMech, nil)}, priv.PrivateHandle)
	if err != nil {
		return nil, err
	}

	return priv.P.Sign(priv.Session, digest)
}

func generateCSR(hpcsPrivateKey HPCSPrivateKey, curveStr string) ([]byte, error) {
	var sa x509.SignatureAlgorithm
	switch curveStr {
	case "P-224", "P-256", "P-384", "P-521":
		sa = x509.ECDSAWithSHA256
	case "ED25519":
		sa = x509.PureEd25519
	case "RSA":
		sa = x509.SHA256WithRSA
	default:
		panic("Unsupport Key Type")
	}

	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         CommonName,
			Country:            []string{Country},
			Organization:       []string{Organization},
			OrganizationalUnit: []string{OrganizationalUnit},
			Locality:           []string{Locality},
			Province:           []string{Province},
		},
		SignatureAlgorithm: sa,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, &hpcsPrivateKey)
	if err != nil {
		return nil, err
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return csrPEM, nil
}

var validECCurves = map[string]asn1.ObjectIdentifier{
	"P-224":   {1, 3, 132, 0, 33},
	"P-256":   {1, 2, 840, 10045, 3, 1, 7},
	"P-384":   {1, 3, 132, 0, 34},
	"P-521":   {1, 3, 132, 0, 35},
	"ED25519": {1, 3, 101, 112},
}

func GenerateHPCSKeyPair(p *pkcs11.Ctx, session pkcs11.SessionHandle, curveStr string, pubLabel []byte, privLabel []byte) HPCSPrivateKey {
	var marshaledOID []byte
	var mech uint
	var publicKeyTemplate []*pkcs11.Attribute
	var privateKeyTemplate []*pkcs11.Attribute

	hpcsPrivateKey := HPCSPrivateKey{
		Session: session,
		P:       p,
	}

	if oid, ok := validECCurves[curveStr]; ok {
		var err error
		marshaledOID, err = asn1.Marshal(oid)
		if err != nil {
			panic(err)
		}
		mech = pkcs11.CKM_EC_KEY_PAIR_GEN
		publicKeyTemplate = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, marshaledOID),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, pubLabel),
		}
		privateKeyTemplate = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, privLabel),
		}
		hpcsPrivateKey.SignMech = pkcs11.CKM_ECDSA_SHA256
		if curveStr == "ED25519" {
			//CKM_IBM_ED25519_SHA512 = CKM_VENDOR_DEFINED + 0x1001c
			hpcsPrivateKey.SignMech = pkcs11.CKM_VENDOR_DEFINED + 0x1001c
		}
	} else if curveStr == "RSA" {
		mech = pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN
		publicKeyTemplate = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{0x1, 0x0, 0x1}),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, pubLabel),
		}
		privateKeyTemplate = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, privLabel),
		}
		hpcsPrivateKey.SignMech = pkcs11.CKM_SHA256_RSA_PKCS
	} else {
		panic("Unsupport Key Type")
	}

	publicHandle, privateHandle, err := p.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(mech, nil)},
		publicKeyTemplate, privateKeyTemplate)
	if err != nil {
		panic(err)
	}

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_KEY_INFO, nil),
	}

	hpcsPrivateKey.PublicHandle = publicHandle
	hpcsPrivateKey.PrivateHandle = privateHandle

	attr, err := p.GetAttributeValue(session, publicHandle, template)
	if err != nil {
		panic(err)
	}
	for _, v := range attr {
		if v.Type == pkcs11.CKA_PUBLIC_KEY_INFO {
			type publicKeyInfo struct {
				Raw       asn1.RawContent
				Algorithm pkix.AlgorithmIdentifier
				PublicKey asn1.BitString
			}
			var parsedData publicKeyInfo

			rest, err := asn1.Unmarshal(v.Value, &parsedData)
			if err != nil {
				panic(err)
			}

			if curveStr == "ED25519" {
				var pki publicKeyInfo
				pki.Algorithm.Algorithm = asn1.ObjectIdentifier{1, 3, 101, 112}
				pki.PublicKey = parsedData.PublicKey
				encodedpki, err := asn1.Marshal(pki)
				if err != nil {
					panic(err)
				}

				hpcsPrivateKey.EncodedPublicKey = encodedpki
			} else {
				_, err := x509.ParsePKIXPublicKey(v.Value[:len(v.Value)-len(rest)])
				if err != nil {
					panic(err)
				}
				hpcsPrivateKey.EncodedPublicKey = v.Value[:len(v.Value)-len(rest)]
			}
		}
	}

	return hpcsPrivateKey
}

func getKeyByUUID(p *pkcs11.Ctx, session pkcs11.SessionHandle, label []byte, isPrivate bool) (pkcs11.ObjectHandle, error) {
	ckaClass := pkcs11.CKO_PUBLIC_KEY
	if isPrivate {
		ckaClass = pkcs11.CKO_PRIVATE_KEY
	}
	keyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, ckaClass),
	}

	err := p.FindObjectsInit(session, keyTemplate)
	if err != nil {
		panic(err)
	}

	publicHandle, _, err := p.FindObjects(session, 1)
	if err != nil {
		panic(err)
	}

	err = p.FindObjectsFinal(session)
	if err != nil {
		panic(err)
	}

	return publicHandle[0], nil
}

func LoadHPCSKeyPair(p *pkcs11.Ctx, session pkcs11.SessionHandle, curveStr string, pubLabel []byte, privLabel []byte) HPCSPrivateKey {
	hpcsPrivateKey := HPCSPrivateKey{
		Session: session,
		P:       p,
	}

	if _, ok := validECCurves[curveStr]; ok {
		hpcsPrivateKey.SignMech = pkcs11.CKM_ECDSA_SHA256
	} else if curveStr == "RSA" {
		hpcsPrivateKey.SignMech = pkcs11.CKM_SHA256_RSA_PKCS
	} else {
		panic("Unsupport Key Type")
	}

	publicHandle, err := getKeyByUUID(p, session, pubLabel, false)
	if err != nil {
		panic(err)
	}

	privateHandle, err := getKeyByUUID(p, session, privLabel, true)
	if err != nil {
		panic(err)
	}

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_KEY_INFO, nil),
	}

	hpcsPrivateKey.PublicHandle = publicHandle
	hpcsPrivateKey.PrivateHandle = privateHandle

	attr, err := p.GetAttributeValue(session, publicHandle, template)
	if err != nil {
		panic(err)
	}
	for _, v := range attr {
		if v.Type == pkcs11.CKA_PUBLIC_KEY_INFO {
			type publicKeyInfo struct {
				Raw       asn1.RawContent
				Algorithm pkix.AlgorithmIdentifier
				PublicKey asn1.BitString
			}
			var parsedData publicKeyInfo

			rest, err := asn1.Unmarshal(v.Value, &parsedData)
			if err != nil {
				panic(err)
			}

			if curveStr == "ed25519" {
				var pki publicKeyInfo
				pki.Algorithm.Algorithm = asn1.ObjectIdentifier{1, 3, 101, 112}
				pki.PublicKey = parsedData.PublicKey
				encodedpki, err := asn1.Marshal(pki)
				if err != nil {
					panic(err)
				}

				hpcsPrivateKey.EncodedPublicKey = encodedpki
			} else {
				_, err := x509.ParsePKIXPublicKey(v.Value[:len(v.Value)-len(rest)])
				if err != nil {
					panic(err)
				}
				hpcsPrivateKey.EncodedPublicKey = v.Value[:len(v.Value)-len(rest)]
			}
		}
	}

	return hpcsPrivateKey
}

func PKCS11Init() (*pkcs11.Ctx, pkcs11.SessionHandle, error) {
	p := pkcs11.New(PKCS11_LIBARY_PATH)
	err := p.Initialize()
	if err != nil {
		return nil, 0, err
	}

	slots, err := p.GetSlotList(true)
	if err != nil {
		return nil, 0, err
	}

	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, 0, err
	}

	err = p.Login(session, pkcs11.CKU_USER, NORMAL_APIKEY)
	if err != nil {
		return nil, 0, err
	}

	return p, session, nil
}

func PKCS11Destroy(p *pkcs11.Ctx, session pkcs11.SessionHandle) {
	p.Logout(session)
	p.CloseSession(session)
	p.Finalize()
	p.Destroy()
}

func main() {
	p, session, err := PKCS11Init()
	if err != nil {
		panic(err)
	}
	defer PKCS11Destroy(p, session)

	var hpcsPrivateKey HPCSPrivateKey
	if EXISTING_KEY {
		hpcsPrivateKey = LoadHPCSKeyPair(p, session, KEY_TYPE, []byte(PUBLIC_CKA_LABEL), []byte(PRIVATE_CKA_LABEL))
	} else {
		hpcsPrivateKey = GenerateHPCSKeyPair(p, session, KEY_TYPE, []byte(PUBLIC_CKA_LABEL), []byte(PRIVATE_CKA_LABEL))
	}

	csrPEM, err := generateCSR(hpcsPrivateKey, KEY_TYPE)
	if err != nil {
		fmt.Println("Error generating CSR:", err)
		return
	}

	csrFile, err := os.Create("csr.pem")
	if err != nil {
		fmt.Println("Error creating CSR file:", err)
		return
	}
	defer csrFile.Close()

	csrFile.Write(csrPEM)
	fmt.Println("CSR generated and saved to csr.pem")
}
