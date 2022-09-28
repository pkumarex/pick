/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package aps

import (
	"crypto/x509"
	"encoding/base64"
	"log"
	"net/url"

	"github.com/intel-secl/intel-secl/v5/pkg/clients/aps"
	"github.com/pkg/errors"
)

func NewApsClient(apsURL, apsRootcacertificate, token string) (aps.APSClient, error) {
	log.Println("aps/aps:NewApsClient() Entering")
	defer log.Println("aps/aps:NewApsClient() Leaving")

	if apsURL == "" || apsRootcacertificate == "" || token == "" {
		log.Fatalln("aps/aps:NewApsClient() Failed to create aps client with empty values")
	}

	apsUrl, err := url.Parse(apsURL)
	if err != nil {
		return nil, errors.Wrap(err, "aps/aps:NewApsClient() Failed to create APS url")
	}

	var caCerts []x509.Certificate
	cmsCA, err := base64.StdEncoding.DecodeString(apsRootcacertificate)
	if err != nil {
		return nil, errors.Wrap(err, "aps/aps:NewApsClient() Failed to decode CMSCA certificate")
	}

	cert, err := x509.ParseCertificate(cmsCA)
	if err != nil {
		return nil, errors.Wrap(err, "aps/aps:NewApsClient() Failed to parse CMSCA certificate")
	}

	caCerts = append(caCerts, *cert)
	apsClient := aps.NewAPSClient(apsUrl, caCerts, token)
	return apsClient, nil
}
