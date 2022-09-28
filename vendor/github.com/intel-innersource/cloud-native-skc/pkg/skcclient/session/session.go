/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package sessionlib

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"time"

	"github.com/pkg/errors"

	pb "github.com/intel-innersource/cloud-native-skc/pkg/cnskcprotobuf"
	"github.com/intel-innersource/cloud-native-skc/pkg/skcclient/config"
	"github.com/intel-innersource/cloud-native-skc/pkg/skcclient/constants"
	"github.com/intel-innersource/cloud-native-skc/pkg/util"
	apsClient "github.com/intel-secl/intel-secl/v5/pkg/clients/aps"
	apsModel "github.com/intel-secl/intel-secl/v5/pkg/model/aps"

	"google.golang.org/grpc"
)

type SessionDetailsStore struct {
	SessionID     []byte
	AttestationID []byte
	SgxQuote      string
}

var SessionDetails *SessionDetailsStore

// Just to check init has been being called only once even if multiple packages import this package.

/* func init() {
	log.Println("session/session:init() Entering")
	defer log.Println("session/session:init() Leaving")

	cfg, err := config.LoadConfiguration()
	if err != nil {
		log.Fatalln("session/session:init() Failed to load config: ", err)
	}

	if !cfg.IsGrpcCrypto {
		// GRPC_CRYPTO is set to false.
		log.Println("session/session:init() Local crypto is selected")
		return
	}

	log.Println("session/session:init() GRPC crypto is selected")

	addr := config.SkcServerAddr
	// Need to check the _ context.CancelFunc
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	log.Printf("session/session:init() SkcClient is trying to connect %v server\n", addr)
	conn, err := grpc.DialContext(ctx, addr, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("did not connect in session pkg: %v", err)
	}
	defer func() {
		err := conn.Close()
		log.Fatalf("session/session:init() failed to close connection %v", err)
	}()

	log.Println("session/session:init() Establishing connection from Init in session package")

	apsClient, err := aps.NewApsClient(cfg.APSURL, cfg.APSRootCACertificate, cfg.APSToken)
	if err != nil {
		log.Fatalf("session/session:init() Failed to create APS client %v\n", err)
	}
	_, err = EstablishSession(conn, apsClient)
	if err != nil {
		log.Println(err)
	}
} */

func CloseSession(conn *grpc.ClientConn, sessionId []byte) (int32, error) {
	log.Println("session/session:CloseSession() Entering")
	defer log.Println("session/session:CloseSession() Leaving")

	c := pb.NewCnskcprotobufClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req := &pb.SessionID{SessionId: sessionId}
	err := req.Validate()
	if err != nil {
		log.Fatalf("session/session:CloseSession() Failed with: %v", err)
		return 2, err
	}
	r, err := c.CloseSession(ctx, req)
	fmt.Println("r.GetResult():", r.GetResult())
	switch r.GetResult() {
	case 1:
		log.Println("session/session:CloseSession() Session closed successfully")
	case 2:
		log.Println("session/session:CloseSession() Session Id does not exist")
		return 2, err
	}

	if err != nil {
		return 0, err
	}

	fmt.Println("calling update details")
	updateSessionDetails(nil, nil)
	return r.GetResult(), nil
}

func EstablishSession(conn *grpc.ClientConn, apsClient apsClient.APSClient) (*SessionDetailsStore, error) {
	log.Println("session/session:EstablishSession() Entering")
	defer log.Println("session/session:EstablishSession() Leaving")

	// Check the session has been established already and it has session id.
	// if yes. return the details.
	// if not, go with the actual flow.
	if SessionDetails != nil {
		log.Println("session/session:EstablishSession() Session has been established already. So returning the details")
		return SessionDetails, nil
	} else {
		if conn == nil {
			return nil, errors.New("could not create session as client connection is empty")
		}

		var sd SessionDetailsStore
		c := pb.NewCnskcprotobufClient(conn)

		cfg, err := config.LoadConfiguration()
		if err != nil {
			log.Fatalf("session/session:EstablishSession() Failed to read config file %v\n", err)
		}

		nonce, httpStatus, err := apsClient.GetNonce()
		if err != nil {
			log.Fatalf("session/session:EstablishSession() Failed to get nonce from APS, failed with Status code %d and error %v\n", httpStatus, err)
		}

		log.Println("session/session:EstablishSession() Successfully retrieved nonce from APS")

		skcserver_token := []byte(cfg.AASToken)

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		req := &pb.SessionRequest{SkcserverToken: skcserver_token, Nonce: []byte(nonce)}
		err = req.Validate()
		if err != nil {
			log.Fatalf("session/session:EstablishSession() Failed with: %v", err)
			return nil, err
		}
		r, err := c.Session(ctx, req)
		if err != nil {
			log.Printf("session/session:EstablishSession() Could not create session: %v\n", err)
			return nil, errors.New("could not create session")
		}
		err = r.Validate()
		if err != nil {
			log.Fatalf("session/session:EstablishSession() Failed with: %v", err)
			return nil, err
		}

		// 1: success, 2: unknown session id, 3: unknown error
		switch r.GetResult() {
		case constants.SESSION_CREATED:
			if bytes.Compare([]byte(nonce), r.GetAttestationId().AttestationId) == 0 {
				log.Println("session/session:EstablishSession() Success in establishing session")
				log.Printf("session/session:EstablishSession() Session ID : %v \n", r.GetSessionId().SessionId)
				log.Printf("session/session:EstablishSession() Attestation Evidence : %v \n", r.GetTeeEvidence())

				pub, err := base64.StdEncoding.DecodeString(r.GetPublicKey())
				if err != nil {
					log.Println("session/session:EstablishSession() Error in reading pub key")
					return nil, errors.Wrap(err, "error in reading pub key")
				}

				loadedPubKey, err := util.LoadPublicKey(pub)
				if err != nil {
					return nil, errors.Wrap(err, "session/session:EstablishSession() Failed to load public key")
				}

				attestationTokenReq := &apsModel.AttestationTokenRequest{
					Quote:    base64.StdEncoding.EncodeToString(r.GetTeeEvidence()),
					UserData: base64.StdEncoding.EncodeToString(loadedPubKey),
				}

				_, statuscode, err := apsClient.GetAttestationToken(nonce, attestationTokenReq)

				if err != nil {

					log.Println("session/session:EstablishSession() Error in attesting the skc server :", err)
					return nil, errors.Wrap(err, "error in attesting the skc server")

				} else {
					log.Println("Statuscode :", statuscode)
					log.Println("session/session:EstablishSession() Skc server attested successfully")
					sd = SessionDetailsStore{
						SessionID:     r.GetSessionId().SessionId,
						AttestationID: []byte(nonce),
						SgxQuote:      base64.StdEncoding.EncodeToString(r.GetTeeEvidence()),
					}

					SessionDetails = &sd
					return SessionDetails, nil
				}
			} else {
				log.Println("session/session:EstablishSession() Error in Attestation Id")
				return nil, errors.New("error in Attestation Id")
			}
		case constants.SESSION_CREATION_FAILED:
			log.Println("session/session:EstablishSession() Unknown session id")
			return nil, errors.New("unknown session id")
		}
	}

	return nil, nil
}

func updateSessionDetails(sessionID []byte, attestationID []byte) {
	log.Println("session/session:updateSessionDetails() Entering")
	defer log.Println("session/session:updateSessionDetails() Leaving")

	SessionDetails.SessionID = sessionID
	SessionDetails.AttestationID = attestationID
}

// Only for testing added this function. Will remove it
func GetSessionDetails() *SessionDetailsStore {
	log.Println("session/session:GetSessionDetails() Entering")
	defer log.Println("session/session:GetSessionDetails() Leaving")

	return SessionDetails
}
