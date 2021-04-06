package sse

import (
	"bytes"
	"errors"
)

var (
	ErrInvalidBlockSize = errors.New("pkcs7: block size must be between 1 and 255 inclusive")
	ErrEmptySlice       = errors.New("pkcs7: source must not be empty slice")
	ErrInvalidPadding   = errors.New("pkcs7: invalid padding")
)

// Pad takes a source byte slice and a block size. It will determine the needed
// amount of padding, n, and appends byte(n) to the source n times.
//
// Example Input: Block Size 8, Source {0xDE, 0xAD, 0xBE, 0xEF}
//
// Expected Output: {0xDE, 0xAD, 0xBE, 0xEF, 0x04, 0x04, 0x04, 0x04}
//
func Pad(src []byte, blockSize int) ([]byte, error) {
	// Only allow 1-255 sized blocks as per standard.
	if blockSize < 1 || blockSize > 255 {
		return nil, ErrInvalidBlockSize
	}

	// Calculate length of needed padding by taking the goal block size and
	// subtracting the overflow of the source.
	padLen := blockSize - len(src)%blockSize

	// Make a byte slice containing the byte to be repeated.
	padding := []byte{byte(padLen)}

	// repeat that byte padLen times
	padding = bytes.Repeat(padding, padLen)

	// Append the padding to the src.
	return append(src, padding...), nil
}

// Unpad takes a source byte slice and will remove any padding added according
// to PKCS#7 specifications. An error is returned for invalid padding.
func Unpad(src []byte) ([]byte, error) {
	length := len(src)

	// If the source is empty it's already invalid.
	if length <= 0 {
		return nil, ErrEmptySlice
	}

	// Get the last byte so we know how many bytes to take off the end.
	padLen := int(src[length-1])

	// If the last byte is 0x00, we have invalid padding. We try to fuzz a bit
	// the error message, sending the same one as when the padding is incorrect.
	if padLen == 0x00 {
		return nil, ErrInvalidPadding
	}

	// If the last byte is more than the total length, this is invalid.
	if padLen > length {
		return nil, ErrInvalidPadding
	}

	// Get original source length assumed based on last byte.
	origLen := length - padLen

	// Get all the padding so we can check it's actually padding and not just an
	// invalid last byte.
	padding := src[origLen:]

	for i := 0; i < padLen; i++ {
		// Make sure all bytes match.
		if padding[i] != byte(padLen) {
			return nil, ErrInvalidPadding
		}
	}

	// Return the source bytes up to the start of the padding.
	return src[:origLen], nil
}
