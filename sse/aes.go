package sse

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// Encrypt takes a message and a key (both as []byte) and will encrypt the
// message with AES using the supplied key. The key must be an appropriate
// length for AES:
//
//     16 = AES-128
//     24 = AES-192
//     32 = AES-256
//
// The message is padded with PKCS#7 Padding and the IV is prepended to the
// ciphertext returned.
//
// For authentication, the HMAC of the encrypted is appended to the ciphertext
// returned.
func Encrypt(message, key []byte) ([]byte, error) {
	if err := keyCheck(key); err != nil {
		return nil, err
	}

	// We have to pad our plaintext so that it is a multiple of the block size.
	// This is because we are using AES in CBC mode.
	plaintext, err := Pad(message, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	//
	// Here we make room in the ciphertext byte slice to prepend the IV of size
	// aes.BlockSize.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))

	// Get a slice of the resulting ciphertext byte slice for the first
	// BlockSize amount of bytes.
	iv := ciphertext[:aes.BlockSize]

	// Fill the IV with random bytes, throw error if one occurs.
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Generate keys for HMAC and AES.
	aesKey, macKey := DeriveKeys(key)
	// Create a new cipher.Block with the given key.
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	// Create a BlockMode to encrypt with the block and the given IV.
	mode := cipher.NewCBCEncrypter(block, iv)

	// Use the BlockMode to encrypt the plaintext and output it into the
	// ciphertext byte slice *after* the point at which the IV is store.
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	// Now let's append the HMAC.
	hmac := HMAC(ciphertext[aes.BlockSize:aes.BlockSize+len(plaintext)], macKey)
	ciphertext = append(ciphertext, hmac[:]...)

	// Return the resulting ciphertext byte slice.
	return ciphertext, nil
}

func Decrypt(message, key []byte) ([]byte, error) {
	if err := keyCheck(key); err != nil {
		return nil, err
	}

	// Make sure the ciphertext is a valid size.
	if len(message) < aes.BlockSize*2+HMACSize {
		return nil, errors.New("sse: message is too short")
	}

	// CBC mode always works in whole blocks.
	if len(message)%aes.BlockSize != 0 {
		return nil, errors.New("sse: message length is not a multiple of the AES Block Size")
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.

	// Remove the IV from the ciphertext
	iv := message[:aes.BlockSize]
	hmac := message[len(message)-HMACSize:]

	// First we'll make a copy of the message bytes so we don't screw up the
	// passed in memory.
	ciphertext := make([]byte, len(message)-aes.BlockSize-HMACSize)

	// Copy in the ciphertext sans IV
	copy(ciphertext, message[aes.BlockSize:len(message)-HMACSize])

	// Derive keys from master key.
	aesKey, macKey := DeriveKeys(key)

	// Check ciphertext against MAC
	if !CheckMAC(ciphertext, hmac, macKey) {
		return nil, errors.New("sse: message's ciphertext does not match MAC")
	}

	// Create a new cipher.Block with the given key.
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	// Create a new block mode to decrypt with the attached IV.
	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)

	// ciphertext has now been decrypted so we need to remove any padding added
	// before encryption.
	plaintext, err := Unpad(ciphertext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func keyCheck(key []byte) error {
	// Check to make sure the key is of an appropriate length.
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return errors.New("sse: key length must be 16, 24, or 32 bytes")
	}

	return nil
}
