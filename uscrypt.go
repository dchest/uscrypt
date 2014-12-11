// Copyright 2013 Dmitry Chestnykh. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package uscrypt implements Unix crypt-like password hashing scheme
// based on scrypt sequential memory-hard key derivation function.
//
// Format of password hashes:
//
//     $scrypt$logN=<LogN>,r=<R>,p=<P>$<SALT>$<PWDHASH>
//
// where LogN, R, P are scrypt cost parameters encoded as decimal numbers (in
// the exact specified order); SALT is a random salt, PWDHASH is the output of
// scrypt, both encoded in Base64 using custom alphabet.
//
package uscrypt

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/scrypt"
)

const (
	maxLogN = 63
	maxInt  = int(^uint(0) >> 1)

	minSaltSize = 0
	minHashSize = 16

	hashId = "scrypt"
)

// Config is used to configure cost and size parameters.
type Config struct {
	LogN int8 // CPU/memory cost (between 1 and 63)
	R    int  // block size (min. 1, must satisfy (R*P) < 2³⁰)
	P    int  // parallelization (min. 1, must satisfy (R*P) < 2³⁰)

	SaltSize int // salt size in bytes
	HashSize int // hash size in bytes (min. 16)
}

// DefaultConfig is a reasonable default configuration for interactive logins.
var DefaultConfig = &Config{LogN: 14, R: 8, P: 1, SaltSize: 32, HashSize: 32}

// Errors.
var (
	ErrMismatchedHashAndPassword = errors.New("uscrypt: hash is not the hash of the given password")
	ErrBadHashFormat             = errors.New("uscrypt: wrong hash format")
)

// IsValid returns true if the config parameters are valid.
//
// The performed validation is machine-independent, which means that IsValid
// can return true on both 32-bit and 64-bit machines, however the actual
// password hashing can fail with error on the former, but not on the latter.
func (c *Config) IsValid() bool {
	if c == nil {
		return false
	}
	if c.LogN <= 0 || c.LogN > maxLogN {
		return false
	}
	if c.R <= 0 || c.P <= 0 {
		return false
	}
	if uint64(c.R)*uint64(c.P) >= 1<<30 {
		return false
	}
	if c.SaltSize < minSaltSize {
		return false
	}
	if c.HashSize < minHashSize {
		return false
	}
	return true
}

func (c *Config) encodedString() string {
	return fmt.Sprintf("logN=%d,r=%d,p=%d", c.LogN, c.R, c.P)
}

// GetConfig extracts configuration parameters from the given hash.
func GetConfig(hash string) (config *Config, err error) {
	config, _, _, err = extractValues(hash)
	return
}

func extractValues(hash string) (config *Config, salt []byte, plainHash []byte, err error) {
	values := strings.Split(hash, "$")
	/*
	   Proper values contain:
	      0 - <empty string>
	      1 - hashId
	      2 - config
	      3 - salt
	      4 - plainHash
	*/
	if len(values) != 5 || values[0] != "" || values[1] != hashId {
		err = ErrBadHashFormat
		return
	}

	cost := strings.Split(values[2], ",")
	/*
		Proper cost contains:
		0 - logN=...
		1 - r=...
		2 - p=...
	*/
	if len(cost) != 3 {
		err = ErrBadHashFormat
		return
	}
	// Extract logN.
	if !strings.HasPrefix(cost[0], "logN=") {
		err = ErrBadHashFormat
		return
	}
	logN, err := strconv.ParseInt(cost[0][len("logN="):], 10, 8)
	if err != nil {
		err = ErrBadHashFormat
		return
	}

	// Extract r.
	if !strings.HasPrefix(cost[1], "r=") {
		err = ErrBadHashFormat
		return
	}
	r, err := strconv.ParseInt(cost[1][len("r="):], 10, 32)
	if err != nil {
		err = ErrBadHashFormat
		return
	}

	// Extract p.
	if !strings.HasPrefix(cost[2], "p=") {
		err = ErrBadHashFormat
		return
	}
	p, err := strconv.ParseInt(cost[2][len("p="):], 10, 32)
	if err != nil {
		err = ErrBadHashFormat
		return
	}

	// Extract salt.
	salt, err = base64Decode(values[3])
	if err != nil {
		err = ErrBadHashFormat
		return
	}

	// Extract plain hash.
	plainHash, err = base64Decode(values[4])
	if err != nil {
		err = ErrBadHashFormat
		return
	}

	// Create config from extracted parameters.
	config = &Config{
		LogN:     int8(logN),
		R:        int(r),
		P:        int(p),
		SaltSize: len(salt),
		HashSize: len(plainHash),
	}
	if !config.IsValid() {
		err = ErrBadHashFormat
		return
	}
	return
}

// HashPassword returns the hash of the password with the given configuration.
// If config is nil, DefaultConfig is used.
//
// To compare the returned hash with the password later, use CompareHashAndPassword.
func HashPassword(password []byte, config *Config) (hash string, err error) {
	if config == nil {
		config = DefaultConfig
	}
	// Generate new random salt.
	salt := make([]byte, config.SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		return "", err
	}
	// Hash password.
	return hashPasswordWithSalt(password, salt[:], config)
}

func hashPasswordWithSalt(password []byte, salt []byte, config *Config) (hash string, err error) {
	// Validate config.
	if !config.IsValid() {
		return "", errors.New("uscrypt: invalid parameters in config")
	}
	// Make sure N won't overflow int.
	N := 1 << uint64(config.LogN)
	if N > maxInt {
		return "", errors.New("uscrypt: logN is too large")
	}
	// Calculate hash.
	h, err := scrypt.Key(password, salt, int(N), config.R, config.P, config.HashSize)
	if err != nil {
		return "", err
	}

	// Encode.
	return fmt.Sprintf("$%s$%s$%s$%s", hashId, config.encodedString(),
		base64Encode(salt), base64Encode(h)), nil
}

// CompareHashAndPassword compares the given hash with the hash
// of the given password and returns nil on success, or an error on failure.
func CompareHashAndPassword(hash string, password []byte) error {
	// Extract values from hash.
	config, salt, _, err := extractValues(hash)
	if err != nil {
		return err
	}
	// Generate a hash from the extracted values.
	currentHash, err := hashPasswordWithSalt(password, salt, config)
	if err != nil {
		return err
	}
	// Compare hashes (no timing attack possible).
	if currentHash != hash {
		return ErrMismatchedHashAndPassword
	}
	return nil
}
