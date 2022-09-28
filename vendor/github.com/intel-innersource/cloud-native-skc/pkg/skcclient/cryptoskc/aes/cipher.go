/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package aes

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"log"
	"os"
	"time"

	"github.com/intel-innersource/cloud-native-skc/pkg/clients/aps"
	pb "github.com/intel-innersource/cloud-native-skc/pkg/cnskcprotobuf"
	"github.com/intel-innersource/cloud-native-skc/pkg/skcclient/config"
	"github.com/intel-innersource/cloud-native-skc/pkg/skcclient/constants"
	cphr "github.com/intel-innersource/cloud-native-skc/pkg/skcclient/cryptoskc/cipher"
	sessionlib "github.com/intel-innersource/cloud-native-skc/pkg/skcclient/session"

	"google.golang.org/grpc"
)

// A cipher is an instance of AES encryption using a particular key.
type aesCipher struct {
	address []byte
	block   cipher.Block
}

func (c *aesCipher) CreateCipherBlock(addr []byte) {
	copy(c.address, addr)
}

func (c *aesCipher) RetrieveCipherAddress() []byte {
	return c.address
}

func (c *aesCipher) RetrieveCipherBlock() cipher.Block {
	return c.block
}

func newCipherGeneric(keyID []byte, block cipher.Block) (cphr.Block, error) {
	log.Println("aes/cipher:newCipherGeneric() Entering")
	defer log.Println("aes/cipher:newCipherGeneric() Leaving")

	aesciph := aesCipher{}
	if keyID != nil {
		// For grpc based crypto operation
		n := len(keyID)
		aesciph.address = make([]byte, n)
		aesciph.CreateCipherBlock(keyID)
	} else {
		// For local golang crypto operation
		aesciph.block = block
	}
	return &aesciph, nil
}

var TestingConn *grpc.ClientConn

var mockcfg *config.Configuration

// NewCipher creates and returns a new cipher.Block.
// The key argument should be the AES key,
// either 16, 24, or 32 bytes to select
// AES-128, AES-192, or AES-256.
func NewCipher(key []byte) (cphr.Block, error) {
	log.Println("crypto/aes/cipher:NewCipher() Entering")
	defer log.Println("crypto/aes/cipher:NewCipher() Leaving")

	if key == nil {
		log.Println("crypto/aes/cipher:NewCipher() Failed to proceed NewCipher with empty Key")
		return nil, errors.New("Failed to proceed NewCipher with empty Key")
	}

	cfg, err := config.LoadConfiguration()
	if err != nil {
		log.Println("aes/cipher:NewCipher() Failed to load config: ", err)
		os.Exit(1)
	}

	if cfg.IsGrpcCrypto {
		// For grpc based crypto operation
		sessID := GetSessionId(cfg)
		conn, err := grpc.Dial(cfg.SkcServerAddr, grpc.WithInsecure(), grpc.WithBlock())
		if err != nil {
			log.Fatalf("aes/cipher:NewCipher() Did not connect: %v", err)
			os.Exit(1)
		}
		defer func() {
			err := conn.Close()
			if err != nil {
				log.Fatalf("aes/cipher:NewCipher() failed to close connection %v", err)
			}
		}()

		c := pb.NewCnskcprotobufClient(conn)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		keyInfo := &pb.KeyInformation{
			KBSURL:    cfg.KBSApiUrl,
			AASToken:  cfg.AASToken,
			CMSRootCA: cfg.KBSRootCACertificate,
		}

		keyIDRequest := &pb.KeyIDRequest{SessionId: &pb.SessionID{SessionId: sessID}, KeyId: key, KeyInfo: keyInfo}
		err = keyIDRequest.Validate()
		if err != nil {
			log.Fatalf("aes/cipher:NewCipher() Failed with: %v", err)
			return nil, err
		}
		r, err := c.NewCipher(ctx, keyIDRequest)
		if err != nil {
			if r != nil && (r.ErrorStatus == constants.INVALID_SESSION || r.ErrorStatus == constants.UNKNOWN_SESSION) {
				log.Fatalf("aes/cipher:NewCipher() Invalid session error: %v", err)
				os.Exit(1)
			}
			log.Fatalf("aes/cipher:NewCipher() Failed with: %v", err)
			return nil, err
		}
		err = r.Validate()
		if err != nil {
			log.Fatalf("aes/cipher:NewCipher() Failed with: %v", err)
			return nil, err
		}
		// Check the status, if session is expired  create new session
		// TBD - discuss with raviraj and Mourad , how to handle attestation ID
		if r.GetAttestationId() == nil {

		}
		return newCipherGeneric(r.GetCipher(), nil)
	} else {
		// TBD - Check Mourad or Raviraj whether we need to check for session validation in local call
		// For local golang crypto operation
		log.Println("aes/cipher:NewCipher() Crypto pkg from GO-lang is used")
		block, err := aes.NewCipher(key)
		if err != nil {
			log.Fatalf("aes/cipher:NewCipher() NewCipher failed with: %v", err)
			return nil, err
		}
		return newCipherGeneric(nil, block)
	}
}

// getting session id
func GetSessionId(cfg *config.Configuration) []byte {
	log.Println("aes/cipher:GetSessionId() Entering")
	defer log.Println("aes/cipher:GetSessionId() Leaving")

	conn, err := grpc.Dial(config.SkcServerAddr, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("aes/cipher:GetSessionId() Did not connect: %v", err)
		os.Exit(1)
	}
	defer func() {
		err := conn.Close()
		if err != nil {
			log.Fatalf("aes/cipher:GetSessionId() failed to close connection %v", err)
		}
	}()

	log.Println("aes/cipher:GetSessionId() try getting session details -  aes")
	apsClient, err := aps.NewApsClient(cfg.APSURL, cfg.APSRootCACertificate, cfg.APSToken)
	if err != nil {
		log.Fatalf("aes/cipher:GetSessionId() Failed to create APS client %v\n", err)
	}
	sessionDetails, err := sessionlib.EstablishSession(conn, apsClient)
	if err != nil {
		log.Fatalf("aes/cipher:GetSessionId() Failed to establish session %v", err.Error())
		os.Exit(1)
	}
	return sessionDetails.SessionID
}
