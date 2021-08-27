package equery

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

type Key [32]byte

func KeyFromSecret(secret string) Key {
	return sha256.Sum256([]byte(secret))
}

func EncryptWithSecret(secret, plaintext string) string {
	key := KeyFromSecret(secret)
	return EncryptWithKey(&key, plaintext)
}

func EncryptWithKey(key *Key, plaintext string) string {
	return EncryptBytesWithKey(key, []byte(plaintext))
}

func EncryptBytesWithKey(key *Key, plaintext []byte) string {
	nonce := [24]byte{}
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		panic("insufficient randomness for nonce generation!")
	}
	encrypted := make([]byte, 0, len(nonce)+len(plaintext))
	encrypted = append(encrypted, nonce[:]...)
	encrypted = secretbox.Seal(encrypted, []byte(plaintext), &nonce, (*[32]byte)(key))
	return base64.URLEncoding.EncodeToString(encrypted)
}

func DecryptWithSecret(secret, eq string) ([]byte, bool) {
	return DecryptBytesWithSecret(secret, []byte(eq))
}

func DecryptWithKey(key *Key, eq string) ([]byte, bool) {
	return DecryptBytesWithKey(key, []byte(eq))
}

func DecryptBytesWithSecret(secret string, eq []byte) ([]byte, bool) {
	key := KeyFromSecret(secret)
	return DecryptBytesWithKey(&key, eq)
}

func DecryptBytesWithKey(key *Key, eq []byte) ([]byte, bool) {
	nonce := [24]byte{}
	decoded := make([]byte, base64.URLEncoding.DecodedLen(len(eq)))
	n, err := base64.URLEncoding.Decode(decoded, eq)
	if err != nil {
		return nil, false
	}
	decoded = decoded[:n]
	if len(decoded) < len(nonce) {
		return nil, false
	}
	copy(nonce[:], decoded[0:len(nonce)])
	box := decoded[len(nonce):]
	return secretbox.Open(nil, box, &nonce, (*[32]byte)(key))
}
