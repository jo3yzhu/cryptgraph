package sse

import (
	"crypto/hmac"
	"crypto/sha256"
)

const HMACSize = sha256.Size

var One = []byte{0x01}
var Two = []byte{0x02}

const (
	BlobSize = 10 // Size of array holding doc IDs
)

// HMAC will compute the MAC with the given message and given key.
func HMAC(message, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

func DeriveKeys(key []byte) (aesKey, macKey []byte) {
	aesInfo := append([]byte("AES-Key"), []byte(One)[:]...)
	macInfo := append([]byte("MAC-Key"), []byte(One)[:]...)
	aesKey = HMAC(aesInfo, key)
	macKey = HMAC(macInfo, key)
	return
}

// CheckMAC reports whether messageMAC is a valid HMAC tag for message.
func CheckMAC(message, messageMAC, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}