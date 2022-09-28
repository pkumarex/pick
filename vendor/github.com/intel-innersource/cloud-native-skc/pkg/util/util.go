/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"log"

	"github.com/pkg/errors"
)

func LoadPublicKey(publicKey []byte) ([]byte, error) {
	log.Println("util/util:LoadPublicKey() Entering")
	defer log.Println("util/util:LoadPublicKey() Leaving")

	if publicKey == nil {
		return nil, errors.New("could not load publickey with empty value")
	}

	pubKeyBlock, _ := pem.Decode(publicKey)
	if pubKeyBlock == nil {
		return nil, errors.New("util/util:LoadPublicKey() unable to decode public key")
	}
	pubKeyBytes, err := x509.ParsePKIXPublicKey(pubKeyBlock.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "util/util:LoadPublicKey() Could not parse envelope public key")
	}

	// Public key format : <exponent:E_SIZE_IN_BYTES><modulus:N_SIZE_IN_BYTES>
	pub := pubKeyBytes.(*rsa.PublicKey)
	pubBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(pubBytes, uint32(pub.E))
	pubBytes = append(pubBytes, pub.N.Bytes()...)
	return pubBytes, nil
}
