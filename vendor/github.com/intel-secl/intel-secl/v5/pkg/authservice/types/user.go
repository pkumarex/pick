/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"bytes"
	"fmt"
	"time"

	"github.com/intel-secl/intel-secl/v5/pkg/authservice/constants"
	"github.com/intel-secl/intel-secl/v5/pkg/lib/common/crypt"

	"golang.org/x/crypto/bcrypt"
)

// User struct is the database schema of a Users table
type User struct {
	ID           string     `json:"user_id" gorm:"primary_key;type:uuid"`
	CreatedAt    time.Time  `json:"-"`
	UpdatedAt    time.Time  `json:"-"`
	DeletedAt    *time.Time `json:"-"`
	Name         string     `json:"username"`
	PasswordHash []byte     `json:"-"`
	PasswordSalt []byte     `json:"-"`
	PasswordCost int        `json:"-"`
	Roles        []Role     `json:"roles,omitempty" gorm:"many2many:user_roles"`
}

type Users []User

func (u *User) CheckPassword(password []byte) error {
	return bcrypt.CompareHashAndPassword(u.PasswordHash, password)
}

func (u *User) ValidateToken(token []byte, serverRand []byte) error {

	hash, err := crypt.GetHashData(append(u.PasswordHash, serverRand...), constants.HashingAlgorithm)
	if err != nil {
		return err
	}
	if bytes.Equal(token, hash) {
		return nil
	}
	return fmt.Errorf("token not validated ")
}
