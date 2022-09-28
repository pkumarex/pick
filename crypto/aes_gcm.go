package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/intel-innersource/cloud-native-skc/pkg/skcclient/cryptoskc/aes"
	"github.com/intel-innersource/cloud-native-skc/pkg/skcclient/cryptoskc/cipher"
	"github.com/spf13/viper"

	"github.com/bndw/pick/crypto/pbkdf2"
	"github.com/bndw/pick/crypto/scrypt"
	"github.com/bndw/pick/errors"
)

var nonceVar []byte

type AESGCMClient struct {
	settings      AESGCMSettings
	keyDerivation KeyDerivation
	Store         AESGCMStore
}

type AESGCMSettings struct {
	KeyLen        int            `json:"keylen,omitempty" toml:"keylen"`
	KeyDerivation string         `json:"keyderivation,omitempty" toml:"keyderivation"`
	PBKDF2        *pbkdf2.PBKDF2 `json:"pbkdf2,omitempty" toml:"pbkdf2"`
	Scrypt        *scrypt.Scrypt `json:"scrypt,omitempty" toml:"scrypt"`
	// Warning: Deprecated. These three Pbkdf2 configs are required for backwards-compatibility :(
	Pbkdf2Hash       string `json:"pbkdf2hash,omitempty" toml:"pbkdf2hash"`
	Pbkdf2Iterations int    `json:"pbkdf2iterations,omitempty" toml:"pbkdf2iterations"`
	Pbkdf2SaltLen    int    `json:"pbkdf2saltlen,omitempty" toml:"pbkdf2saltlen"`
}

type AESGCMStore struct {
	Salt       []byte `json:"salt"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

const (
	aesGCMDefaultKeyLen        = cipherLenAES256
	aesGCMDefaultKeyDerivation = keyDerivationTypePBKDF2
)

func DefaultAESGCMSettings() *AESGCMSettings {
	return &AESGCMSettings{
		KeyLen:        aesGCMDefaultKeyLen,
		KeyDerivation: aesGCMDefaultKeyDerivation,
		PBKDF2:        pbkdf2.New(),
		Scrypt:        scrypt.New(),
	}
}

func NewAESGCMClient(settings *AESGCMSettings) (*AESGCMClient, error) {

	if settings.PBKDF2 == nil {
		// Probably a safe which uses the old config, backwards-compatibility mode
		settings.PBKDF2 = pbkdf2.New()
		settings.PBKDF2.Hash = settings.Pbkdf2Hash
		settings.PBKDF2.Iterations = settings.Pbkdf2Iterations
		settings.PBKDF2.SaltLen = settings.Pbkdf2SaltLen
	}
	var kdf KeyDerivation
	switch settings.KeyDerivation {
	default:
		if settings.KeyDerivation != "" {
			fmt.Println("Invalid keyDerivation, using default")
		}
		fallthrough
	case keyDerivationTypePBKDF2:
		// Remove other settings
		// TODO(leon): This is shitty.
		settings.Scrypt = nil
		kdf = settings.PBKDF2
	case keyDerivationTypeScrypt:
		// Remove other settings
		// TODO(leon): This is shitty.
		settings.PBKDF2 = nil
		kdf = settings.Scrypt
	}
	return &AESGCMClient{
		settings:      *settings,
		keyDerivation: kdf,
	}, nil
}

func (c *AESGCMClient) keyLen() int {
	keyLen := c.settings.KeyLen
	switch keyLen {
	default:
		if keyLen != 0 {
			fmt.Println("Invalid keyLen, using default")
		}
		return aesGCMDefaultKeyLen
	case cipherLenAES128:
	case cipherLenAES192:
	case cipherLenAES256:
	}
	return keyLen
}

func (c *AESGCMClient) deriveKey(password []byte, keyLen int) ([]byte, []byte, error) {
	return c.keyDerivation.DeriveKey(password, keyLen)
}

func (c *AESGCMClient) deriveKeyWithSalt(password, salt []byte, keyLen int) ([]byte, error) {
	return c.keyDerivation.DeriveKeyWithSalt(password, salt, keyLen)
}

func (c *AESGCMClient) Decrypt(data []byte, password []byte) ([]byte, error) {
	var store AESGCMStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, err
	}

	/* key, err := c.deriveKeyWithSalt(password, store.Salt, c.keyLen())
	if err != nil {
		return nil, err
	} */

	viper.AutomaticEnv()
	key := viper.GetString("KEY")
	if key == "" {
		log.Println("sampleapp/sampleapp:CryptoFunctions() KEY is not provided in env")
		os.Exit(1)
	}

	ac, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(ac)
	if err != nil {
		return nil, err
	}

	nonceVar := ReadFile()

	fmt.Println("Nonce at Decrypt place -> ", base64.StdEncoding.EncodeToString(nonceVar))
	fmt.Println("Nonce at Decrypt place -> ", base64.StdEncoding.EncodeToString(store.Ciphertext))

	decryptNonceSize := gcm.NonceSize()

	if len(store.Ciphertext) < int(decryptNonceSize) {

		fmt.Println("sampleapp/sampleapp:CryptoFunctions() Invalid cipher text")

	}

	nonce, ciphertext := store.Ciphertext[:decryptNonceSize], store.Ciphertext[decryptNonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.ErrSafeDecryptionFailed
	}

	return plaintext, nil
}

func (c *AESGCMClient) Encrypt(plaintext []byte, password []byte) (data []byte, err error) {
	fmt.Println("crypto/aes_gcm.go entered Encrypt ")
	defer fmt.Println("crypto/aes_gcm.go left Encrypt ")
	/* key, salt, err := c.deriveKey(password, c.keyLen())
	if err != nil {
		return
	} */

	viper.AutomaticEnv()
	key := viper.GetString("KEY")
	fmt.Println("crypto/aes_gcm.go entered Encrypt key value -> ", key)
	if key == "" {
		log.Println("sampleapp/sampleapp:CryptoFunctions() KEY is not provided in env")
		os.Exit(1)
	}

	ac, err := aes.NewCipher([]byte(key))
	if err != nil {
		fmt.Println("Failed to perform NewCipher on Encrypt err -> ", err)
		return
	}

	gcm, err := cipher.NewGCM(ac)
	if err != nil {
		fmt.Println("Failed to perform NewGCM err -> ", err)
		return
	}
	var nonceVar []byte
	_, err1 := os.Stat("/root/nonce.txt")
	if os.IsNotExist(err1) || err1 != nil {
		fmt.Println("****Nonce file does not exist******")
		nonce := make([]byte, gcm.NonceSize())
		if _, err = rand.Read(nonce); err != nil {
			fmt.Println("Failed to perform rand.Read() err -> ", err)
			return
		}

		c.Store.Nonce = nonce

		fmt.Println("********Nonce at Encrypt place 1 ********", base64.StdEncoding.EncodeToString(c.Store.Nonce))

		nonceVar = nonce
		CreateFile(nonceVar)
	} else {
		fmt.Println("****Nonce file exists******")
		nonceVar = ReadFile()
	}

	fmt.Println("************Nonce at encrypt place 2 *************", base64.StdEncoding.EncodeToString(nonceVar))

	ciphertext := gcm.Seal(nonceVar, nonceVar, plaintext, nil)

	fmt.Println("******Cipher text******", base64.StdEncoding.EncodeToString(ciphertext))

	store := AESGCMStore{
		//Salt:       salt,
		Nonce:      nonceVar,
		Ciphertext: ciphertext,
	}
	data, err = json.Marshal(store)
	if err != nil {
		fmt.Println("Failed to decode err -> ", err)
		return
	}

	return
}

func CreateFile(nonce []byte) {

	// fmt package implements formatted
	// I/O and has functions like Printf
	// and Scanf
	fmt.Printf("Writing to a file in Go lang\n")

	// in case an error is thrown it is received
	// by the err variable and Fatalf method of
	// log prints the error message and stops
	// program execution
	file, err := os.Create("/root/nonce.txt")

	if err != nil {
		log.Fatalf("failed creating file: %s", err)
	}

	// Defer is used for purposes of cleanup like
	// closing a running file after the file has
	// been written and main //function has
	// completed execution
	defer file.Close()

	// len variable captures the length
	// of the string written to the file.
	/* len, err := file.WriteString("Welcome to GeeksforGeeks." +
	" This program demonstrates reading and writing" +
	" operations to a file in Go lang.") */

	len, err := file.Write(nonce)

	if err != nil {
		log.Fatalf("failed writing to file: %s", err)
	}

	// Name() method returns the name of the
	// file as presented to Create() method.
	fmt.Printf("\nFile Name: %s", file.Name())
	fmt.Printf("\nLength: %d bytes", len)
}

func ReadFile() []byte {

	fmt.Printf("\n\nReading a file in Go lang\n")
	fileName := "/root/nonce.txt"

	// The ioutil package contains inbuilt
	// methods like ReadFile that reads the
	// filename and returns the contents.
	data, err := ioutil.ReadFile("/root/nonce.txt")
	if err != nil {
		log.Panicf("failed reading data from file: %s", err)
	}
	fmt.Printf("\nFile Name: %s", fileName)
	fmt.Printf("\nSize: %d bytes", len(data))
	fmt.Printf("\nData: %s", data)

	return data

}
