package cipher

import "crypto/cipher"

type Block interface {
	CreateCipherBlock(addr []byte)
	RetrieveCipherAddress() []byte
	RetrieveCipherBlock() cipher.Block
}

type AEAD interface {
	CreateGcmBlock(addr []byte)
	RetrieveGcmBlock() []byte
	NonceSize() int
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}
