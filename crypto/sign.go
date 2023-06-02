package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"
	"github.com/xslasd/x-oidc/ecode"
	"os"
)

type JWTCertifier interface {
	GenerateJWT(claims interface{}) (string, error)
	ParseJWT(token string, payload interface{}) error
	Encrypt(str string) (string, error)
	Decrypt(encrypted string) (string, error)
	LoadPublicKey() (jose.JSONWebKey, error)
	ClaimHash(claim string) (string, error)
}

type JoseRSAJWT struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	algorithm  jose.SignatureAlgorithm
}

func (j JoseRSAJWT) ClaimHash(claim string) (string, error) {
	hash, err := GetHashAlgorithm(j.algorithm)
	if err != nil {
		return "", err
	}
	return HashString(hash, claim, true), nil
}

func (j JoseRSAJWT) Encrypt(str string) (string, error) {
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, j.publicKey, []byte(str))
	return hex.EncodeToString(ciphertext), err
}

func (j JoseRSAJWT) Decrypt(encrypted string) (string, error) {
	data, err := hex.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, j.privateKey, data)
	return string(plaintext), err
}
func (j JoseRSAJWT) LoadPublicKey() (jose.JSONWebKey, error) {
	return jose.JSONWebKey{Key: j.publicKey, KeyID: uuid.New().String(), Algorithm: string(j.algorithm), Use: "sig"}, nil
}

func NewJoseRSAJWT(privatePath string, algorithm jose.SignatureAlgorithm) (*JoseRSAJWT, error) {
	rsa := new(JoseRSAJWT)
	privateKeyByt, err := os.ReadFile(privatePath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(privateKeyByt)
	if block == nil {
		return nil, ecode.PrivateKeyInvalid
	}
	// Parse the public key
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsa.privateKey = privateKey
	rsa.publicKey = &privateKey.PublicKey
	rsa.algorithm = algorithm
	return rsa, nil
}

func (j JoseRSAJWT) GenerateJWT(claims interface{}) (string, error) {
	signerOpts := jose.SignerOptions{}
	signerOpts.WithType("JWT")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: j.algorithm, Key: j.privateKey}, &signerOpts)
	if err != nil {
		fmt.Println("Error creating signer:", err)
		return "", err
	}
	// Signed JWT
	token, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		fmt.Println("Error signing token:", err)
		return "", err
	}
	return token, nil
}

func (j JoseRSAJWT) ParseJWT(token string, payload interface{}) error {
	parsedToken, err := jwt.ParseSigned(token)
	if err != nil {
		fmt.Println("Error parsing token:", err)
		return err
	}
	err = parsedToken.Claims(j.publicKey, &payload)
	if err != nil {
		fmt.Println("Error verifying token:", err)
		return err
	}
	return nil
}

//
//type JoseHMACJWT struct {
//	signingKey   []byte
//	algorithm    jose.SignatureAlgorithm
//	keyAlgorithm jose.KeyAlgorithm
//}
//
//func (j JoseHMACJWT) Encrypt(str string) (string, error) {
//	return EncryptAES(str, string(j.signingKey))
//}
//
//func (j JoseHMACJWT) Decrypt(encrypted string) (string, error) {
//	return DecryptAES(encrypted, string(j.signingKey))
//}
//func (j JoseHMACJWT) LoadPublicKey() (jose.JSONWebKey, error) {
//	return jose.JSONWebKey{}, nil
//}
//
//func NewJoseHMACJWT(signingKey string, algorithm jose.SignatureAlgorithm) (*JoseHMACJWT, error) {
//	hmac := new(JoseHMACJWT)
//	hmac.signingKey = []byte(signingKey)
//	hmac.algorithm = algorithm
//	return hmac, nil
//}
//
//func (j JoseHMACJWT) GenerateJWT(claims interface{}) (string, error) {
//	// 创建一个 JWT 签名者
//	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: j.signingKey}, nil)
//	if err != nil {
//		fmt.Println("Error creating signer:", err)
//		return "", err
//	}
//	// Signed JWT
//	token, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
//	if err != nil {
//		fmt.Println("Error signing token:", err)
//		return "", err
//	}
//	return token, nil
//}
//
//func (j JoseHMACJWT) ParseJWT(token string, payload interface{}) error {
//	parsedToken, err := jose.ParseSigned(token)
//	if err != nil {
//		fmt.Println("Error parsing token:", err)
//		return err
//	}
//	b, err := parsedToken.Verify(j.signingKey)
//	if err != nil {
//		fmt.Println("Error verifying token:", err)
//		return err
//	}
//	err = json.Unmarshal(b, payload)
//	return err
//}
//
//func Sign(object interface{}, signingKey jose.SigningKey) (string, error) {
//	signer, err := jose.NewSigner(signingKey, &jose.SignerOptions{})
//	if err != nil {
//		return "", err
//	}
//	payload, err := json.Marshal(object)
//	if err != nil {
//		return "", err
//	}
//	result, err := signer.Sign(payload)
//	if err != nil {
//		return "", err
//	}
//	return result.CompactSerialize()
//}
