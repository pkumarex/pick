/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// Configuration is the global configuration struct that is marshalled/unmarshalled to a persisted yaml file
type Configuration struct {
	KBSApiUrl            string `mapstructure:"KBS_API_URL"`
	Key                  string `mapstructure:"KEY"`
	TestMode             string `mapstructure:"TEST_MODE"`
	SkcServerAddr        string `mapstructure:"SKC_SERVER_ADDR"`
	KBSRootCACertificate string `mapstructure:"KBS_ROOT_CA"`
	APSURL               string `mapstructure:"APS_URL"`
	APSToken             string `mapstructure:"APS_TOKEN"`
	APSRootCACertificate string `mapstructure:"APS_ROOT_CA"`
	AASToken             string `mapstructure:"AAS_TOKEN"`
	IsGrpcCrypto         bool   `mapstructure:"IS_GRPC_CRYPTO"`
}

var SkcServerAddr string

// this function sets the configure file name and type
func init() {
	viper.AutomaticEnv()
	SkcServerAddr = viper.GetString("SKC_SERVER_ADDR")
}

func LoadConfiguration() (config *Configuration, err error) {
	log.Println("config/config:LoadConfiguration() Entering")
	defer log.Println("config/config:LoadConfiguration() Leaving")

	ret := Configuration{}
	ret.Key = viper.GetString("KEY")
	ret.KBSApiUrl = viper.GetString("KBS_API_URL")
	ret.APSURL = viper.GetString("APS_URL")
	ret.APSToken = viper.GetString("APS_TOKEN")
	ret.AASToken = viper.GetString("AAS_TOKEN")
	ret.KBSRootCACertificate = viper.GetString("KBS_ROOT_CA")
	ret.APSRootCACertificate = viper.GetString("APS_ROOT_CA")
	ret.SkcServerAddr = viper.GetString("SKC_SERVER_ADDR")
	ret.IsGrpcCrypto = viper.GetBool("IS_GRPC_CRYPTO")

	if ret.Key == "" {
		log.Fatalln("config/config:validateConfiguration() KEY cannot be empty")
	}

	if ret.IsGrpcCrypto {
		// Check for other env variables only in case of grpc crypto
		ret.validateConfiguration()
	}
	return &ret, nil
}

func (cfg *Configuration) validateConfiguration() {
	log.Println("config/config:validateConfiguration() Entering")
	defer log.Println("config/config:validateConfiguration() Leaving")

	// Following are mandatory with out these values we cannot proceed furher.
	if cfg.KBSApiUrl == "" {
		log.Fatalln("config/config:validateConfiguration() KBS URL cannot be empty")
	}

	if cfg.SkcServerAddr == "" {
		log.Fatalln("config/config:validateConfiguration() SKC_SERVER_ADDR cannot be empty")
	}

	if cfg.APSURL == "" {
		log.Fatalln("config/config:validateConfiguration() APS_URL cannot be empty")
	}

	if cfg.APSToken == "" {
		log.Fatalln("config/config:validateConfiguration() APS_TOKEN cannot be empty")
	}

	if cfg.AASToken == "" {
		log.Fatalln("config/config:validateConfiguration() AAS_TOKEN cannot be empty")
	}

	if cfg.KBSRootCACertificate == "" {
		log.Fatalln("config/config:validateConfiguration() KBS_ROOT_CA cannot be empty")
	}

	if cfg.APSRootCACertificate == "" {
		log.Fatalln("config/config:validateConfiguration() APS_ROOT_CA cannot be empty")
	}
}
