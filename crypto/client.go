package crypto

import (
	"fmt"
)

type Client interface {
	Decrypt(ciphertext, password []byte) (plaintext []byte, err error)
	Encrypt(plaintext, password []byte) (ciphertext []byte, err error)
}

func New(config Config) (Client, error) {
	switch config.Type {
	default:
		if config.Type != "" {
			fmt.Println("Invalid encryption type, using default")
		}
		return NewAESOpenPGPClient(config)
	case "aes-openpgp":
		return NewAESOpenPGPClient(config)
	}
}
