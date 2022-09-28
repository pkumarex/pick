/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package aps

import (
	"crypto/x509"
	"net/url"

	commLog "github.com/intel-secl/intel-secl/v5/pkg/lib/common/log"
	"github.com/intel-secl/intel-secl/v5/pkg/model/aps"
)

var defaultLog = commLog.GetDefaultLogger()

type APSClient interface {
	GetJwtSigningCertificate() ([]byte, error)
	GetNonce() (string, int, error)
	GetAttestationToken(string, *aps.AttestationTokenRequest) ([]byte, int, error)
}

func NewAPSClient(apsURL *url.URL, certs []x509.Certificate, token string) APSClient {
	return &apsClient{
		BaseURL:  apsURL,
		CaCerts:  certs,
		JwtToken: token,
	}
}

type apsClient struct {
	BaseURL  *url.URL
	CaCerts  []x509.Certificate
	JwtToken string
}
