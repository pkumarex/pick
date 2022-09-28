/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package aps

import (
	"github.com/intel-secl/intel-secl/v5/pkg/clients/util"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/constants"
	"github.com/pkg/errors"
	"net/http"
	"net/url"
)

func (a *apsClient) GetJwtSigningCertificate() ([]byte, error) {
	defaultLog.Trace("aps/jwt_certificate:GetJwtSigningCertificate() Entering")
	defer defaultLog.Trace("aps/jwt_certificate:GetJwtSigningCertificate() Leaving")

	jwtCertURL, _ := url.Parse("jwt-signing-certificates")
	reqURL := a.BaseURL.ResolveReference(jwtCertURL)
	req, err := http.NewRequest("GET", reqURL.String(), nil)
	if err != nil {
		return nil, errors.Wrap(err, "aps/jwt_certificate:GetJwtSigningCertificate() Error initializing get jwt signing certificate request")
	}

	// Set the request header
	req.Header.Set("Accept", constants.HTTPMediaTypePemFile)
	rsp, err := util.SendNoAuthRequest(req, a.CaCerts)
	if err != nil {
		return nil, errors.Wrap(err, "aps/jwt_certificate:GetJwtSigningCertificate() Error response from get jwt signing certificate request")
	}

	return rsp, nil
}
