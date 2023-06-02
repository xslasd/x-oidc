package crypto

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/go-jose/go-jose/v3"
	"hash"
)

var ErrUnsupportedAlgorithm = errors.New("unsupported signing algorithm")

func GetHashAlgorithm(sigAlgorithm jose.SignatureAlgorithm) (hash.Hash, error) {
	switch sigAlgorithm {
	case jose.RS256, jose.ES256, jose.PS256, jose.HS256:
		return sha256.New(), nil
	case jose.RS384, jose.ES384, jose.PS384, jose.HS384:
		return sha512.New384(), nil
	case jose.RS512, jose.ES512, jose.PS512, jose.HS512:
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, sigAlgorithm)
	}
}

func ClaimHash(claim string, sigAlgorithm jose.SignatureAlgorithm) (string, error) {
	hash, err := GetHashAlgorithm(sigAlgorithm)
	if err != nil {
		return "", err
	}
	return HashString(hash, claim, true), nil
}

func HashString(hash hash.Hash, s string, firstHalf bool) string {
	hash.Write([]byte(s))
	size := hash.Size()
	if firstHalf {
		size = size / 2
	}
	sum := hash.Sum(nil)[:size]
	return base64.RawURLEncoding.EncodeToString(sum)
}
