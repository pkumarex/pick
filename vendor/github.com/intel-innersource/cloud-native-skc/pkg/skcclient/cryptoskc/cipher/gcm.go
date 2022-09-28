/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package cipher

import (
	"context"
	"crypto/cipher"
	"log"
	"os"
	"time"

	"github.com/intel-innersource/cloud-native-skc/pkg/clients/aps"
	pb "github.com/intel-innersource/cloud-native-skc/pkg/cnskcprotobuf"
	"github.com/intel-innersource/cloud-native-skc/pkg/skcclient/config"
	"github.com/intel-innersource/cloud-native-skc/pkg/skcclient/constants"
	sessionlib "github.com/intel-innersource/cloud-native-skc/pkg/skcclient/session"

	"google.golang.org/grpc"
)

// gcm represents a Galois Counter Mode with a specific key. See
// https://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
type gcm struct {
	cipher  Block
	address []byte
	aead    cipher.AEAD
}

func (g *gcm) CreateGcmBlock(addr []byte) {
	copy(g.address, addr)
}

func (g *gcm) RetrieveGcmBlock() []byte {
	return g.address
}

func newGCMGeneric(cphr Block, gcmID []byte, aead cipher.AEAD) (AEAD, error) {
	log.Println("cipher/gcm:newGCMGeneric() Entering")
	defer log.Println("cipher/gcm:newGCMGeneric() Leaving")

	gcmObj := gcm{}
	if gcmID != nil {
		// For grpc based crypto operation
		n := len(gcmID)
		gcmObj.address = make([]byte, n)
		gcmObj.cipher = cphr
		gcmObj.CreateGcmBlock(gcmID)
	} else {
		// For local golang crypto operation
		gcmObj.aead = aead
	}

	return &gcmObj, nil
}

func (g *gcm) NonceSize() int {
	log.Println("cipher/gcm:NonceSize() Entering")
	defer log.Println("cipher/gcm:NonceSize() Leaving")

	cfg, err := config.LoadConfiguration()
	if err != nil {
		log.Fatal("cipher/gcm:NonceSize() cannot load config:", err)
	}

	if cfg.IsGrpcCrypto {
		// For grpc based crypto operation
		sessID := GetSessionId(cfg)
		conn, err := grpc.Dial(cfg.SkcServerAddr, grpc.WithInsecure(), grpc.WithBlock())
		if err != nil {
			log.Fatalf("cipher/gcm:NonceSize() did not connect: %v", err)
			os.Exit(1)
		}
		defer func() {
			err := conn.Close()
			if err != nil {
				log.Fatalf("cipher/gcm:NonceSize() failed to close connection %v", err)
			}
		}()

		c := pb.NewCnskcprotobufClient(conn)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		req := &pb.NonceSizeRequest{SessionId: &pb.SessionID{SessionId: sessID}, Gcm: g.address}
		err = req.Validate()
		if err != nil {
			log.Fatalf("cipher/gcm:NonceSize() Failed with: %v", err)
			return 0
		}
		r, err := c.NonceSize(ctx, req)
		if err != nil {
			if r != nil && (r.ErrorStatus == constants.INVALID_SESSION || r.ErrorStatus == constants.UNKNOWN_SESSION) {
				log.Fatalf("cipher/gcm:NonceSize() Invalid session error: %v", err)
				os.Exit(1)
			}
			log.Fatalf("cipher/gcm:NonceSize() Failed to perform NonceSize request %v", err)
			return 0
		}
		err = r.Validate()
		if err != nil {
			log.Fatalf("cipher/gcm:NonceSize() Failed with: %v", err)
			return 0
		}
		return int(r.GetNonceSize())

	} else {
		// For local golang crypto operation
		return g.aead.NonceSize()
	}
}

func (g *gcm) Seal(dst, nonce, plainText, additionalData []byte) []byte {
	log.Println("cipher/gcm:Seal() Entering")
	defer log.Println("cipher/gcm:Seal() Leaving")

	cfg, err := config.LoadConfiguration()
	if err != nil {
		log.Fatal("cipher/gcm:Seal() cannot load config:", err)
	}

	if cfg.IsGrpcCrypto {
		// For grpc based crypto operation
		log.Println("cipher/gcm:Seal() session id:", GetSessionId(cfg))
		sessID := GetSessionId(cfg)
		conn, err := grpc.Dial(cfg.SkcServerAddr, grpc.WithInsecure(), grpc.WithBlock())
		if err != nil {
			log.Fatalf("cipher/gcm:Seal() did not connect: %v", err)
		}
		defer func() {
			err := conn.Close()
			if err != nil {
				log.Fatalf("cipher/gcm:Seal() failed to close connection %v", err)
			}
		}()

		c := pb.NewCnskcprotobufClient(conn)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		req := &pb.SealRequest{
			Dst:            dst,
			Nonce:          nonce,
			Plaintext:      plainText,
			Additionaldata: additionalData,
			Gcm:            g.address,
			SessionId:      &pb.SessionID{SessionId: sessID},
		}

		err = req.Validate()
		if err != nil {
			log.Fatalf("cipher/gcm:Seal() Failed with: %v", err)
			return nil
		}

		r, err := c.Seal(ctx, req)
		if err != nil {
			if r != nil && (r.ErrorStatus == constants.INVALID_SESSION || r.ErrorStatus == constants.UNKNOWN_SESSION) {
				log.Fatalf("cipher/gcm:Seal() Invalid session error: %v", err)
				os.Exit(1)
			}
			log.Fatalf("cipher/gcm:Seal() Failed to perform seal request %v", err)
			return nil
		}
		err = r.Validate()
		if err != nil {
			log.Fatalf("cipher/gcm:Seal() Failed with: %v", err)
			return nil
		}

		return r.GetCiphertext()
	} else {
		// For local golang crypto operation
		return g.aead.Seal(dst, nonce, plainText, additionalData)
	}
}

func (g *gcm) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	log.Println("cipher/gcm:Open() Entering")
	defer log.Println("cipher/gcm:Open() Leaving")

	cfg, err := config.LoadConfiguration()
	if err != nil {
		log.Fatal("cipher/gcm:Open() Cannot load config:", err)
	}

	if cfg.IsGrpcCrypto {
		// For grpc based crypto operation
		log.Println("cipher/gcm:Open() Session id:", GetSessionId(cfg))
		sessID := GetSessionId(cfg)
		conn, err := grpc.Dial(cfg.SkcServerAddr, grpc.WithInsecure(), grpc.WithBlock())
		if err != nil {
			log.Fatalf("cipher/gcm:Open() Did not connect: %v", err)
			os.Exit(1)
		}
		defer func() {
			err := conn.Close()
			if err != nil {
				log.Fatalf("cipher/gcm:Open() failed to close connection %v", err)
			}
		}()

		c := pb.NewCnskcprotobufClient(conn)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		req := &pb.DecryptRequest{SessionId: &pb.SessionID{SessionId: sessID}, Gcm: g.address, Dst: dst, Nonce: nonce, Ciphertext: ciphertext, Additionaldata: additionalData}
		err = req.Validate()
		if err != nil {
			log.Fatalf("crypto/cipher/gcm:Open() Failed with: %v", err)
			return nil, err
		}

		r, err := c.Open(ctx, req)
		if err != nil {
			if r != nil && (r.ErrorStatus == constants.INVALID_SESSION || r.ErrorStatus == constants.UNKNOWN_SESSION) {
				log.Fatalf("crypto/cipher/gcm:Open() Invalid session error: %v", err)
				os.Exit(1)
			}
			log.Fatalf("crypto/cipher/gcm:Open() Failed to perform Open request %v", err)
			return nil, err
		}
		err = r.Validate()
		if err != nil {
			log.Fatalf("crypto/cipher/gcm:Open() Failed with: %v", err)
			return nil, err
		}

		return r.GetPlaintext(), nil
	} else {
		// For local golang crypto operation
		return g.aead.Open(dst, nonce, ciphertext, additionalData)
	}
}

// In general, the GHASH operation performed by this implementation of GCM is not constant-time.
// An exception is when the underlying Block was created by aes.NewCipher
// on systems with hardware support for AES. See the crypto/aes package documentation for details.
func NewGCM(cphrObject Block) (AEAD, error) {
	log.Println("cipher/gcm:NewGCM() Entering")
	defer log.Println("cipher/gcm:NewGCM() Leaving")

	cfg, err := config.LoadConfiguration()
	if err != nil {
		log.Fatal("cipher/gcm:NewGCM() Cannot load config:", err)
	}

	if cfg.IsGrpcCrypto {
		// For grpc based crypto operation
		log.Println("cipher/gcm:NewGCM() Session id :", GetSessionId(cfg))
		sessID := GetSessionId(cfg)
		conn, err := grpc.Dial(cfg.SkcServerAddr, grpc.WithInsecure(), grpc.WithBlock())
		if err != nil {
			log.Fatalf("cipher/gcm:NewGCM() Did not connect: %v", err)
			os.Exit(1)
		}
		defer func() {
			err := conn.Close()
			if err != nil {
				log.Fatalf("cipher/gcm:NewGCM() failed to close connection %v", err)
			}
		}()

		c := pb.NewCnskcprotobufClient(conn)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		req := &pb.GcmRequest{SessionId: &pb.SessionID{SessionId: sessID}, Cipher: cphrObject.RetrieveCipherAddress()}
		err = req.Validate()
		if err != nil {
			log.Fatalf("cipher/gcm:NewGCM() Failed with: %v", err)
			return nil, err
		}
		r, err := c.NewGCM(ctx, req)
		if err != nil {
			if r != nil && (r.ErrorStatus == constants.INVALID_SESSION || r.ErrorStatus == constants.UNKNOWN_SESSION) {
				log.Fatalf("cipher/gcm:NewGCM() Invalid session error: %v", err)
				os.Exit(1)
			}
			log.Fatalf("cipher/gcm:NewGCM() Unable to create NewGCM failed with error %v", err)
			return nil, err
		}
		err = r.Validate()
		if err != nil {
			log.Fatalf("cipher/gcm:NewGCM() Failed with: %v", err)
			return nil, err
		}

		return newGCMGeneric(cphrObject, r.GetGcm(), nil)
	} else {
		// For local golang crypto operation
		// TBD - Check Mourad or Raviraj whether we need to check for session validation in local call
		gcmObject, err := cipher.NewGCM(cphrObject.RetrieveCipherBlock())
		if err != nil {
			log.Fatal("cipher/gcm:NewGCM() Error in creating cipher AEAD gcm object")
			return nil, err
		}
		return newGCMGeneric(nil, nil, gcmObject)
	}
}

// getting session id
func GetSessionId(cfg *config.Configuration) []byte {
	log.Println("cipher/gcm:GetSessionId() Entering")
	defer log.Println("cipher/gcm:GetSessionId() Leaving")

	conn, err := grpc.Dial(config.SkcServerAddr, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("cipher/gcm:GetSessionId() Did not connect: %v", err)
	}
	defer func() {
		err := conn.Close()
		if err != nil {
			log.Fatalf("cipher/gcm:GetSessionId() failed to close connection %v", err)
		}
	}()

	log.Println("cipher/gcm:GetSessionId() Try getting session details - cipher")
	apsClient, err := aps.NewApsClient(cfg.APSURL, cfg.APSRootCACertificate, cfg.APSToken)
	if err != nil {
		log.Fatalf("cipher/gcm:GetSessionId() Failed to create APS client %v\n", err)
	}
	sessionDetails, err := sessionlib.EstablishSession(conn, apsClient)
	if err != nil {
		log.Fatalf("cipher/gcm:GetSessionId() Failed to establish session %v", err.Error())
	}
	return sessionDetails.SessionID
}
