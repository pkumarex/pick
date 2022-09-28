/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package aps

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/intel-secl/intel-secl/v5/pkg/clients/util"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/model/aps"
	"github.com/pkg/errors"
)

// GetNonce sends a POST to /attestation-token to create a new Nonce to be used as userdata for quote generation
func (a *apsClient) GetNonce() (string, int, error) {
	defaultLog.Trace("aps/attestation_token:GetNonce() Entering")
	defer defaultLog.Trace("aps/attestation_token:GetNonce() Leaving")

	tokenURL, _ := url.Parse("attestation-token")
	reqURL := a.BaseURL.ResolveReference(tokenURL)
	req, err := http.NewRequest("POST", reqURL.String(), nil)
	if err != nil {
		return "", http.StatusInternalServerError, errors.Wrap(err, "aps/attestation_token:GetNonce() Error initializing http request")
	}

	// Set the request headers
	req.Header.Set("Authorization", "Bearer "+a.JwtToken)
	rsp, err := util.GetHTTPResponse(req, a.CaCerts, false)
	if err != nil {
		if rsp != nil {
			return "", rsp.StatusCode, errors.Wrap(err, "aps/attestation_token:GetNonce() Invalid status code received from APS")
		}
		return "", http.StatusInternalServerError, errors.Wrap(err, "aps/attestation_token:GetNonce() Error while retrieving nonce from APS")
	}
	defer func() {
		derr := rsp.Body.Close()
		if derr != nil {
			defaultLog.WithError(derr).Error("aps/attestation_token:GetNonce() Error closing response body")
		}
	}()

	// Parse response headers
	nonce := rsp.Header.Get("Nonce")
	return nonce, rsp.StatusCode, nil
}

// GetAttestationToken sends a POST to /attestation-token to create a new Attestation token with the specified quote attributes
func (a *apsClient) GetAttestationToken(nonce string, tokenRequest *aps.AttestationTokenRequest) ([]byte, int, error) {
	defaultLog.Trace("aps/attestation_token:GetAttestationToken() Entering")
	defer defaultLog.Trace("aps/attestation_token:GetAttestationToken() Leaving")

	reqBytes, err := json.Marshal(tokenRequest)
	if err != nil {
		return nil, http.StatusInternalServerError, errors.Wrap(err, "aps/attestation_token:GetAttestationToken() Error marshalling attestation token request")
	}

	tokenURL, _ := url.Parse("attestation-token")
	reqURL := a.BaseURL.ResolveReference(tokenURL)
	req, err := http.NewRequest("POST", reqURL.String(), bytes.NewBuffer(reqBytes))
	if err != nil {
		return nil, http.StatusInternalServerError, errors.Wrap(err, "aps/attestation_token:GetAttestationToken() Error initializing http request")
	}

	// Set the request headers
	req.Header.Set("Accept", constants.HTTPMediaTypeJwt)
	req.Header.Set("Authorization", "Bearer "+a.JwtToken)
	req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
	req.Header.Set("Nonce", nonce)
	rsp, err := util.GetHTTPResponse(req, a.CaCerts, false)
	if err != nil {
		if rsp != nil {
			return nil, rsp.StatusCode, errors.Wrap(err, "aps/attestation_token:GetAttestationToken() Invalid status code received from APS")
		}
		return nil, http.StatusInternalServerError, errors.Wrap(err, "aps/attestation_token:GetAttestationToken() Error while retrieving attestation token from APS")
	}

	defer func() {
		derr := rsp.Body.Close()
		if derr != nil {
			defaultLog.WithError(derr).Error("Error closing response body")
		}
	}()

	//create byte array of HTTP response body
	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return nil, http.StatusInternalServerError, errors.Wrap(err, "aps/attestation_token:GetAttestationToken() Error reading response body "+
			"while retrieving attestation token")
	}

	return body, rsp.StatusCode, nil
}
