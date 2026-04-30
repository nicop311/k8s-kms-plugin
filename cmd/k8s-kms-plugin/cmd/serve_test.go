/*
 * Copyright 2026 Thales Group
 * SPDX-License-Identifier: MIT
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestAlgorithmFamily_Set_Valid verifies that every documented slug is accepted.
func TestAlgorithmFamily_Set_Valid(t *testing.T) {
	valid := []string{"aes-gcm", "aes-cbc", "rsa-oaep", "ml-kem"}
	for _, v := range valid {
		a := AlgorithmFamilyAESGCM // start from a known state
		assert.NoErrorf(t, a.Set(v), "Set(%q) should succeed", v)
		assert.Equal(t, AlgorithmFamily(v), a)
	}
}

// TestAlgorithmFamily_Set_Invalid verifies that jose constants, size-qualified names,
// and empty strings are all rejected.
func TestAlgorithmFamily_Set_Invalid(t *testing.T) {
	invalid := []string{
		"",            // empty
		"aes",         // incomplete
		"aes-256-gcm", // size-qualified — user should not need to know the size
		"A256GCM",     // jose constant
		"RSA-OAEP",    // jose constant (wrong case)
		"MLKEM768",    // jose constant
		"unknown",
	}
	for _, v := range invalid {
		a := AlgorithmFamilyAESGCM
		assert.Errorf(t, a.Set(v), "Set(%q) should fail", v)
	}
}

// TestAlgorithmFamily_Set_DoesNotMutateOnError verifies that a failed Set() leaves
// the receiver unchanged.
func TestAlgorithmFamily_Set_DoesNotMutateOnError(t *testing.T) {
	a := AlgorithmFamilyRSAOAEP
	_ = a.Set("invalid")
	assert.Equal(t, AlgorithmFamilyRSAOAEP, a)
}

func TestAlgorithmFamily_String(t *testing.T) {
	cases := []struct {
		a    AlgorithmFamily
		want string
	}{
		{AlgorithmFamilyAESGCM, "aes-gcm"},
		{AlgorithmFamilyAESCBC, "aes-cbc"},
		{AlgorithmFamilyRSAOAEP, "rsa-oaep"},
		{AlgorithmFamilyMLKEM, "ml-kem"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.a.String())
	}
}

func TestAlgorithmFamily_Type(t *testing.T) {
	a := AlgorithmFamilyAESGCM
	assert.Equal(t, "algorithmFamily", a.Type())
}

// TestValidateAlgorithmFamily covers all valid slugs and a representative set of
// invalid inputs.
func TestValidateAlgorithmFamily(t *testing.T) {
	valid := []string{"aes-gcm", "aes-cbc", "rsa-oaep", "ml-kem"}
	for _, v := range valid {
		assert.NoErrorf(t, validateAlgorithmFamily(v), "validateAlgorithmFamily(%q) should succeed", v)
	}

	invalid := []string{
		"",
		"aes-256-gcm",
		"A256GCM",
		"RSA-OAEP",
		"MLKEM768",
		"aes gcm", // space instead of dash
	}
	for _, v := range invalid {
		err := validateAlgorithmFamily(v)
		assert.Errorf(t, err, "validateAlgorithmFamily(%q) should fail", v)
		assert.Contains(t, err.Error(), "must be one of")
	}
}

// TestSanitizeViperFlagsServe_Valid confirms that a valid AlgorithmFamily passes
// without error.
func TestSanitizeViperFlagsServe_Valid(t *testing.T) {
	for _, v := range []string{"aes-gcm", "aes-cbc", "rsa-oaep", "ml-kem"} {
		f := &ViperFlagsServe{AlgorithmFamily: v}
		assert.NoErrorf(t, sanitizeViperFlagsServe(f), "sanitize should accept %q", v)
	}
}

// TestSanitizeViperFlagsServe_Invalid verifies that an unsupported value (e.g. from
// a config file) is rejected with a flag-prefixed error message.
func TestSanitizeViperFlagsServe_Invalid(t *testing.T) {
	f := &ViperFlagsServe{AlgorithmFamily: "aes-256-gcm"}
	err := sanitizeViperFlagsServe(f)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "--algorithm-family")
	assert.Contains(t, err.Error(), "must be one of")
}

// TestSanitizeViperFlagsServe_Empty verifies that an empty string (e.g. missing
// config key) is rejected.
func TestSanitizeViperFlagsServe_Empty(t *testing.T) {
	f := &ViperFlagsServe{AlgorithmFamily: ""}
	err := sanitizeViperFlagsServe(f)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "--algorithm-family")
}