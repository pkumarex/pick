package crypto

type Client interface {
	Decrypt(data, password []byte) (plaintext []byte, err error)
	Encrypt(plaintext, password []byte) (data []byte, err error)
}

type KeyDerivation interface {
	DeriveKey(password []byte, keyLen int) (key []byte, salt []byte, err error)
	DeriveKeyWithSalt(password, salt []byte, keyLen int) (key []byte, err error)
}

func New(config *Config) (Client, error) {

	// Remove other settings
	// TODO(leon): This is shitty.
	config.OpenPGPSettings = nil
	config.ChaCha20Poly1305Settings = nil
	return NewAESGCMClient(config.AESGCMSettings)

	// switch config.Type {
	// default:
	// 	if config.Type != "" {
	// 		fmt.Println("Invalid encryption type, using default")
	// 	}
	// 	fallthrough
	// case ConfigTypeChaChaPoly:
	// 	// Remove other settings
	// 	// TODO(leon): This is shitty.
	// 	config.OpenPGPSettings = nil
	// 	config.AESGCMSettings = nil
	// 	return NewChaCha20Poly1305Client(config.ChaCha20Poly1305Settings)
	// case ConfigTypeOpenPGP:
	// 	// Remove other settings
	// 	// TODO(leon): This is shitty.
	// 	config.AESGCMSettings = nil
	// 	config.ChaCha20Poly1305Settings = nil
	// 	return NewOpenPGPClient(config.OpenPGPSettings)
	// case ConfigTypeAESGCM:
	// 	// Remove other settings
	// 	// TODO(leon): This is shitty.
	// 	config.OpenPGPSettings = nil
	// 	config.ChaCha20Poly1305Settings = nil
	// 	return NewAESGCMClient(config.AESGCMSettings)
	// }
}
