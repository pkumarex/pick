/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package aps

import (
	modelaps "github.com/intel-secl/intel-secl/v5/pkg/model/aps"
	"github.com/stretchr/testify/mock"
)

func NewMockApsClient() *MockApsClient {
	mockApsClient := MockApsClient{}
	return &mockApsClient
}

type MockApsClient struct {
	mock.Mock
}

func (a *MockApsClient) GetAttestationToken(nonce string, tokenRequest *modelaps.AttestationTokenRequest) ([]byte, int, error) {
	args := a.Called(nonce, tokenRequest)
	return []byte(args.Get(0).(string)), args.Get(1).(int), args.Error(2)
}

func (a *MockApsClient) GetNonce() (string, int, error) {
	args := a.Called()
	return args.Get(0).(string), args.Get(1).(int), args.Error(2)

}

func (a *MockApsClient) GetJwtSigningCertificate() ([]byte, error) {
	args := a.Called()
	return args.Get(0).([]byte), args.Error(1)
}
