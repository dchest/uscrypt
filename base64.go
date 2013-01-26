// Copyright 2013 Dmitry Chestnykh. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uscrypt

import (
	"encoding/base64"
	"strings"
)

var enc = base64.NewEncoding("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")

func base64Encode(b []byte) string {
	// Decode.
	dst := enc.EncodeToString(b)
	// Remove padding.
	return strings.TrimRight(dst, "=")
}

func base64Decode(s string) ([]byte, error) {
	// Append padding.
	padLen := 4 - (len(s) % 4)
	s += "===="[:padLen]
	// Encode.
	return enc.DecodeString(s)
}
