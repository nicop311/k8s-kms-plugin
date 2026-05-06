/*
 * Copyright 2026 Thales Group
 * SPDX-License-Identifier: MIT
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

package e2e

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/ThalesGroup/crypto11"
	"github.com/ThalesGroup/k8s-kms-plugin/pkg/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const rotationPlaintext = "the quick brown fox jumps over the lazy dog — k8s-kms-plugin rotation e2e"

// ── Rotation helpers ──────────────────────────────────────────────────────────

// captureEncryptResponse starts a standalone plugin with the given extra serve
// args, encrypts rotationPlaintext, stops the plugin, and returns the ciphertext
// and keyId from the EncryptResponse.
func captureEncryptResponse(t *testing.T, extraArgs ...string) (ciphertext, keyId string) {
	t.Helper()
	sock := socketPath(t)
	t.Cleanup(func() { os.Remove(sock) })

	proc := startPlugin(t, sock, extraArgs...)
	defer proc.stop()
	waitForSocket(t, sock)

	plaintextB64 := base64.StdEncoding.EncodeToString([]byte(rotationPlaintext))
	body := fmt.Sprintf(`{"plaintext":%q,"uid":"rot-pre-enc"}`, plaintextB64)

	var resp encryptResponse
	require.NoError(t, json.Unmarshal(callGrpcurl(t, sock, "Encrypt", body), &resp))
	require.NotEmpty(t, resp.Ciphertext, "pre-rotation Encrypt.ciphertext must not be empty")
	require.NotEmpty(t, resp.KeyId, "pre-rotation Encrypt.keyId must not be empty")
	return resp.Ciphertext, resp.KeyId
}

// kmsRotationRoundtrip exercises a running rotation plugin on socket.
// It runs four sequential sub-tests:
//  1. Status — must return a keyId different from oldKeyId (the rotated key).
//  2. EncryptWithNewKey — Encrypt must succeed and return the new keyId.
//  3. DecryptWithNewKey — round-trip decryption of the just-encrypted ciphertext.
//  4. DecryptOldCiphertext — oldCiphertext (encrypted with oldKeyId before rotation)
//     must still decrypt to rotationPlaintext.
func kmsRotationRoundtrip(t *testing.T, socket, oldCiphertext, oldKeyId string) {
	t.Helper()

	plaintextB64 := base64.StdEncoding.EncodeToString([]byte(rotationPlaintext))

	var newKeyId, activeCiphertext string

	t.Run("Status", func(t *testing.T) {
		var resp statusResponse
		require.NoError(t, json.Unmarshal(callGrpcurl(t, socket, "Status", `{}`), &resp))
		require.NotEmpty(t, resp.KeyId, "Status.keyId must not be empty")
		assert.NotEqual(t, oldKeyId, resp.KeyId, "rotation plugin must advertise a different active key than the rotated one")
		newKeyId = resp.KeyId
	})
	if t.Failed() {
		return
	}

	t.Run("EncryptWithNewKey", func(t *testing.T) {
		body := fmt.Sprintf(`{"plaintext":%q,"uid":"rot-enc-new"}`, plaintextB64)
		var resp encryptResponse
		require.NoError(t, json.Unmarshal(callGrpcurl(t, socket, "Encrypt", body), &resp))
		require.NotEmpty(t, resp.Ciphertext, "Encrypt.ciphertext must not be empty")
		assert.Equal(t, newKeyId, resp.KeyId, "Encrypt.keyId must match the active key from Status")
		activeCiphertext = resp.Ciphertext
	})
	if t.Failed() {
		return
	}

	t.Run("DecryptWithNewKey", func(t *testing.T) {
		body := fmt.Sprintf(`{"ciphertext":%q,"uid":"rot-dec-new","key_id":%q}`, activeCiphertext, newKeyId)
		var resp decryptResponse
		require.NoError(t, json.Unmarshal(callGrpcurl(t, socket, "Decrypt", body), &resp))
		recovered, err := base64.StdEncoding.DecodeString(resp.Plaintext)
		require.NoError(t, err, "base64-decode Decrypt.plaintext (new key)")
		assert.Equal(t, rotationPlaintext, string(recovered))
	})

	t.Run("DecryptOldCiphertext", func(t *testing.T) {
		body := fmt.Sprintf(`{"ciphertext":%q,"uid":"rot-dec-old","key_id":%q}`, oldCiphertext, oldKeyId)
		var resp decryptResponse
		require.NoError(t, json.Unmarshal(callGrpcurl(t, socket, "Decrypt", body), &resp))
		recovered, err := base64.StdEncoding.DecodeString(resp.Plaintext)
		require.NoError(t, err, "base64-decode Decrypt.plaintext (old key)")
		assert.Equal(t, rotationPlaintext, string(recovered))
	})
}

// oldTokenArgs returns the common --old-p11-* connection flags pointing to the
// shared e2e SoftHSM token. In these tests both old and new keys live on the
// same token, so these values mirror testConfig.
func oldTokenArgs() []string {
	return []string{
		"--old-p11-lib",   testConfig.Path,
		"--old-p11-label", testConfig.TokenLabel,
		"--old-p11-pin",   testConfig.Pin,
	}
}

// runRotationTest is the shared two-phase rotation harness.
//
//   - oldServeArgs: extra args for startPlugin when pre-encrypting with the old key.
//   - newServeArgs: extra args for startPlugin for the new (active) key side.
//   - oldRotationArgs: args placed after the "rotation" sub-command (old key identity
//     and algorithm flags consumed by rotationCmd).
func runRotationTest(t *testing.T, oldServeArgs, newServeArgs, oldRotationArgs []string) {
	t.Helper()

	// Phase 1: standalone plugin with the old key — capture a ciphertext to rotate.
	oldCiphertext, oldKeyId := captureEncryptResponse(t, oldServeArgs...)

	// Phase 2: rotation plugin.
	// startPlugin already prepends: serve --socket .. --p11-lib .. --p11-label .. --p11-pin .. --log-level debug
	// We append: <newServeArgs> rotation <oldRotationArgs>
	rotationExtraArgs := make([]string, 0, len(newServeArgs)+1+len(oldRotationArgs))
	rotationExtraArgs = append(rotationExtraArgs, newServeArgs...)
	rotationExtraArgs = append(rotationExtraArgs, "rotation")
	rotationExtraArgs = append(rotationExtraArgs, oldRotationArgs...)

	sock := socketPath(t)
	t.Cleanup(func() { os.Remove(sock) })

	proc := startPlugin(t, sock, rotationExtraArgs...)
	defer proc.stop()
	waitForSocket(t, sock)

	kmsRotationRoundtrip(t, sock, oldCiphertext, oldKeyId)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// TestRotation_FromAESGCM rotates from AES-256-GCM to a new AES-256-GCM key.
// This exercises the AlgAESGCM branch of decryptWithContext on the rotation path.
func TestRotation_FromAESGCM(t *testing.T) {
	oldKekLabel := newLabel(t)
	newKekLabel := newLabel(t)

	oldKek, err := testCtx.GenerateSecretKeyWithLabel(newKeyID(t), []byte(oldKekLabel), 256, crypto11.CipherAES)
	require.NoError(t, err, "generate old AES-256-GCM KEK")
	t.Cleanup(func() { _ = oldKek.Delete() })

	newKek, err := testCtx.GenerateSecretKeyWithLabel(newKeyID(t), []byte(newKekLabel), 256, crypto11.CipherAES)
	require.NoError(t, err, "generate new AES-256-GCM KEK")
	t.Cleanup(func() { _ = newKek.Delete() })

	runRotationTest(t,
		[]string{
			"--algorithm-family", string(providers.AlgAESGCM),
			"--p11-key-label", oldKekLabel,
		},
		[]string{
			"--algorithm-family", string(providers.AlgAESGCM),
			"--p11-key-label", newKekLabel,
		},
		append(oldTokenArgs(),
			"--old-algorithm-family", string(providers.AlgAESGCM),
			"--old-p11-key-label", oldKekLabel,
		),
	)
}

// TestRotation_FromAESCBC rotates from AES-256-CBC+HMAC-SHA256 to a new AES-256-GCM key.
// This exercises the AlgAESCBC branch of decryptWithContext on the rotation path,
// including HMAC key lookup via --old-p11-hmac-label.
func TestRotation_FromAESCBC(t *testing.T) {
	oldKekLabel  := newLabel(t)
	oldHmacLabel := newLabel(t)
	newKekLabel  := newLabel(t)

	oldKek, err := testCtx.GenerateSecretKeyWithLabel(newKeyID(t), []byte(oldKekLabel), 256, crypto11.CipherAES)
	require.NoError(t, err, "generate old AES-256-CBC KEK")
	t.Cleanup(func() { _ = oldKek.Delete() })

	// HMAC key: CKK_GENERIC_SECRET with CKA_SIGN=true so CKM_SHA256_HMAC is permitted.
	hmacAttrs, err := crypto11.NewAttributeSetWithIDAndLabel(newKeyID(t), []byte(oldHmacLabel))
	require.NoError(t, err)
	require.NoError(t, hmacAttrs.Set(crypto11.CkaSign, true))
	require.NoError(t, hmacAttrs.Set(crypto11.CkaVerify, true))
	oldHmac, err := testCtx.GenerateSecretKeyWithAttributes(hmacAttrs, 256, crypto11.CipherGeneric)
	require.NoError(t, err, "generate old HMAC-SHA256 key")
	t.Cleanup(func() { _ = oldHmac.Delete() })

	newKek, err := testCtx.GenerateSecretKeyWithLabel(newKeyID(t), []byte(newKekLabel), 256, crypto11.CipherAES)
	require.NoError(t, err, "generate new AES-256-GCM KEK")
	t.Cleanup(func() { _ = newKek.Delete() })

	runRotationTest(t,
		[]string{
			"--algorithm-family", string(providers.AlgAESCBC),
			"--p11-key-label",  oldKekLabel,
			"--p11-hmac-label", oldHmacLabel,
		},
		[]string{
			"--algorithm-family", string(providers.AlgAESGCM),
			"--p11-key-label", newKekLabel,
		},
		append(oldTokenArgs(),
			"--old-algorithm-family", string(providers.AlgAESCBC),
			"--old-p11-key-label",  oldKekLabel,
			"--old-p11-hmac-label", oldHmacLabel,
		),
	)
}

// TestRotation_FromRSAOAEP rotates from RSA-2048-OAEP to a new AES-256-GCM key.
// This exercises the AlgRSAOAEP branch of decryptWithContext on the rotation path.
func TestRotation_FromRSAOAEP(t *testing.T) {
	oldKekLabel := newLabel(t)
	newKekLabel := newLabel(t)

	oldKP, err := testCtx.GenerateRSAKeyPairWithLabel(newKeyID(t), []byte(oldKekLabel), 2048)
	require.NoError(t, err, "generate old RSA-2048-OAEP key pair")
	t.Cleanup(func() { _ = oldKP.Delete() })

	newKek, err := testCtx.GenerateSecretKeyWithLabel(newKeyID(t), []byte(newKekLabel), 256, crypto11.CipherAES)
	require.NoError(t, err, "generate new AES-256-GCM KEK")
	t.Cleanup(func() { _ = newKek.Delete() })

	runRotationTest(t,
		[]string{
			"--algorithm-family", string(providers.AlgRSAOAEP),
			"--p11-key-label", oldKekLabel,
		},
		[]string{
			"--algorithm-family", string(providers.AlgAESGCM),
			"--p11-key-label", newKekLabel,
		},
		append(oldTokenArgs(),
			"--old-algorithm-family", string(providers.AlgRSAOAEP),
			"--old-p11-key-label", oldKekLabel,
		),
	)
}

// TestRotation_FromMLKEM rotates from ML-KEM-768 to a new AES-256-GCM key.
// This exercises decryptMLKEMWithContext on the rotation path.
// Skipped automatically on tokens that do not support CKM_ML_KEM_KEY_PAIR_GEN
// (SoftHSMv2 and earlier); requires SoftHSMv3.
func TestRotation_FromMLKEM(t *testing.T) {
	oldKekLabel := newLabel(t)
	newKekLabel := newLabel(t)

	oldKP, err := testCtx.GenerateMLKEMKeyPairWithLabel(newKeyID(t), []byte(oldKekLabel), crypto11.MLKEM768)
	if err != nil {
		t.Skipf("ML-KEM key generation not supported by this token: %v"+
			" — requires SoftHSMv3 from https://github.com/pqctoday-org/pqctoday-hsm", err)
	}
	t.Cleanup(func() { _ = oldKP.Delete() })

	newKek, err := testCtx.GenerateSecretKeyWithLabel(newKeyID(t), []byte(newKekLabel), 256, crypto11.CipherAES)
	require.NoError(t, err, "generate new AES-256-GCM KEK")
	t.Cleanup(func() { _ = newKek.Delete() })

	runRotationTest(t,
		[]string{
			"--algorithm-family", string(providers.AlgMLKEM),
			"--p11-key-label", oldKekLabel,
		},
		[]string{
			"--algorithm-family", string(providers.AlgAESGCM),
			"--p11-key-label", newKekLabel,
		},
		append(oldTokenArgs(),
			"--old-algorithm-family", string(providers.AlgMLKEM),
			"--old-p11-key-label", oldKekLabel,
		),
	)
}
