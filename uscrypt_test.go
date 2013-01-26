// Copyright 2013 Dmitry Chestnykh. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uscrypt

import (
	"testing"
)

var password = []byte("password")

func TestHashPassword(t *testing.T) {
	hash, err := HashPassword(password, nil)
	if err != nil {
		t.Fatalf("%s", err)
	}
	// Make sure the same password is correct.
	if err := CompareHashAndPassword(hash, password); err != nil {
		t.Fatalf("%s", err)
	}
	// Make sure different password is incorrect.
	if err := CompareHashAndPassword(hash, []byte("incorrect")); err == nil {
		t.Fatalf("matched different passwords")
	}
	// Make sure incorrect hash is invalid.
	incorrectHash := make([]byte, len(hash))
	copy(incorrectHash[len(hash)-8:], []byte("xxxxxxxx"))
	if err := CompareHashAndPassword(string(incorrectHash), password); err == nil {
		t.Fatalf("matched password with incorrect hash")
	}
}
