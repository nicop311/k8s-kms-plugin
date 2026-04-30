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
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ThalesGroup/crypto11"
	"github.com/ThalesGroup/k8s-kms-plugin/pkg/providers"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	e2ePlaintext = "the quick brown fox jumps over the lazy dog — k8s-kms-plugin e2e"

	// pluginStartTimeout is the maximum time to wait for the plugin unix socket
	// to appear. PKCS#11 library loading + token connection can be slow.
	pluginStartTimeout = 20 * time.Second

	// pluginTestTimeout is the context deadline for the entire plugin subprocess.
	pluginTestTimeout = 60 * time.Second
)

// ── Unique-name helpers ───────────────────────────────────────────────────────

// newKeyID returns a UUID as bytes, suitable for PKCS#11 CKA_ID.
func newKeyID(t *testing.T) []byte {
	t.Helper()
	id, err := uuid.NewRandom()
	require.NoError(t, err)
	b, err := id.MarshalText()
	require.NoError(t, err)
	return b
}

// newLabel returns a short unique label (max ~16 chars) safe for PKCS#11.
func newLabel(t *testing.T) string {
	t.Helper()
	id, err := uuid.NewRandom()
	require.NoError(t, err)
	return "e2e-" + id.String()[:8]
}

// socketPath returns a unique, short unix socket path under /tmp.
// Keeps total path length well under the 108-byte Linux limit.
func socketPath(t *testing.T) string {
	t.Helper()
	id, err := uuid.NewRandom()
	require.NoError(t, err)
	return fmt.Sprintf("/tmp/kms-%s.sock", id.String()[:8])
}

// ── Plugin subprocess management ──────────────────────────────────────────────

type pluginProcess struct {
	cmd    *exec.Cmd
	cancel context.CancelFunc
	logPath string
}

// startPlugin launches k8s-kms-plugin serve with the given extra flags.
// The subprocess stdout+stderr go to a log file; on test failure the log is
// printed via t.Log so the failure reason is visible in `go test -v` output.
func startPlugin(t *testing.T, socket string, extraArgs ...string) *pluginProcess {
	t.Helper()

	logPath := socket + ".log"
	logFile, err := os.Create(logPath)
	require.NoError(t, err)

	t.Cleanup(func() {
		logFile.Close()
		// Always print the plugin log so failures are self-explanatory.
		if data, rerr := os.ReadFile(logPath); rerr == nil && len(data) > 0 {
			t.Logf("=== plugin log (%s) ===\n%s", logPath, string(data))
		}
		os.Remove(logPath)
	})

	ctx, cancel := context.WithTimeout(context.Background(), pluginTestTimeout)

	args := append(
		[]string{
			"serve",
			"--socket",    socket,
			"--p11-lib",   testConfig.Path,
			"--p11-label", testConfig.TokenLabel,
			"--p11-pin",   testConfig.Pin,
			"--log-level", "debug",
		},
		extraArgs...,
	)

	t.Logf("starting plugin: %s %v", pluginBin, args)
	cmd := exec.CommandContext(ctx, pluginBin, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	require.NoError(t, cmd.Start(), "start k8s-kms-plugin")

	return &pluginProcess{cmd: cmd, cancel: cancel, logPath: logPath}
}

func (p *pluginProcess) stop() {
	p.cancel()
	_ = p.cmd.Wait()
}

// waitForSocket polls every 200 ms until the unix socket file appears,
// calling t.Fatalf if pluginStartTimeout elapses.
func waitForSocket(t *testing.T, socket string) {
	t.Helper()
	t.Logf("waiting for socket %s (timeout %s)", socket, pluginStartTimeout)
	deadline := time.Now().Add(pluginStartTimeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socket); err == nil {
			t.Logf("socket ready: %s", socket)
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timeout (%s) waiting for plugin socket %s", pluginStartTimeout, socket)
}

// ── gRPC roundtrip via grpcurl ────────────────────────────────────────────────

type statusResponse struct {
	KeyId string `json:"keyId"`
}
type encryptResponse struct {
	Ciphertext string `json:"ciphertext"`
	KeyId      string `json:"keyId"`
}
type decryptResponse struct {
	Plaintext string `json:"plaintext"` // base64-encoded bytes field
}

// callGrpcurl runs a single grpcurl call and returns the combined output.
// On a non-zero exit the full output is included in the test error.
func callGrpcurl(t *testing.T, socket, method, body string) []byte {
	t.Helper()
	// grpcurl with -unix flag: the address must be the bare socket path.
	// unix:// prefix is NOT added when -unix is present.
	// grpcurl requires -import-path when -proto receives an absolute path.
	// Address format matches scripts/grpcurl/grpcurl-roundtrip-test.sh: -unix unix://<socket>.
	cmd := exec.Command(
		"grpcurl",
		"-plaintext",
		"-import-path", filepath.Dir(protoFile),
		"-proto", filepath.Base(protoFile),
		"-d", body,
		"-unix",
		"unix://"+socket,
		"v2.KeyManagementService."+method,
	)
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "grpcurl %s failed\ncmd: %s\noutput:\n%s", method, cmd.String(), string(out))
	t.Logf("grpcurl %s response: %s", method, string(out))
	return out
}

// grpcRoundtrip performs Status → Encrypt → Decrypt and asserts the recovered
// plaintext equals the original.
func grpcRoundtrip(t *testing.T, socket string) {
	t.Helper()

	// Status — retrieve the active key ID.
	var status statusResponse
	require.NoError(t, json.Unmarshal(callGrpcurl(t, socket, "Status", `{}`), &status))
	require.NotEmpty(t, status.KeyId, "Status.keyId must not be empty")
	t.Logf("Status.keyId = %s", status.KeyId)

	// Encrypt — plaintext must be base64-encoded for the bytes proto field.
	plaintextB64 := base64.StdEncoding.EncodeToString([]byte(e2ePlaintext))
	encBody := fmt.Sprintf(`{"plaintext":%q,"uid":"e2e-enc"}`, plaintextB64)
	var enc encryptResponse
	require.NoError(t, json.Unmarshal(callGrpcurl(t, socket, "Encrypt", encBody), &enc))
	require.NotEmpty(t, enc.Ciphertext, "Encrypt.ciphertext must not be empty")

	// Decrypt — verify roundtrip.
	decBody := fmt.Sprintf(`{"ciphertext":%q,"uid":"e2e-dec","key_id":%q}`, enc.Ciphertext, enc.KeyId)
	var dec decryptResponse
	require.NoError(t, json.Unmarshal(callGrpcurl(t, socket, "Decrypt", decBody), &dec))

	recovered, err := base64.StdEncoding.DecodeString(dec.Plaintext)
	require.NoError(t, err, "base64-decode Decrypt.plaintext")
	assert.Equal(t, e2ePlaintext, string(recovered))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// testAESGCM generates an AES key of the requested bit size, starts the plugin,
// and exercises a full Status → Encrypt → Decrypt roundtrip.
// The key size is auto-detected by the plugin via CKA_VALUE_LEN — the user
// only needs to specify --algorithm-family aes-gcm.
func testAESGCM(t *testing.T, bitSize int) {
	t.Helper()

	label := newLabel(t)
	key, err := testCtx.GenerateSecretKeyWithLabel(newKeyID(t), []byte(label), bitSize, crypto11.CipherAES)
	require.NoErrorf(t, err, "GenerateSecretKeyWithLabel AES-%d", bitSize)
	t.Cleanup(func() { _ = key.Delete() })

	sock := socketPath(t)
	t.Cleanup(func() { os.Remove(sock) })

	proc := startPlugin(t, sock,
		"--algorithm-family", string(providers.AlgAESGCM),
		"--p11-key-label", label,
	)
	defer proc.stop()

	waitForSocket(t, sock)
	grpcRoundtrip(t, sock)
}

func TestPlugin_AESGCM_128bit(t *testing.T) { testAESGCM(t, 128) }
func TestPlugin_AESGCM_192bit(t *testing.T) { testAESGCM(t, 192) }
func TestPlugin_AESGCM_256bit(t *testing.T) { testAESGCM(t, 256) }

func TestPlugin_AESCBC(t *testing.T) {
	kekLabel := newLabel(t)
	hmacLabel := newLabel(t)

	kek, err := testCtx.GenerateSecretKeyWithLabel(newKeyID(t), []byte(kekLabel), 256, crypto11.CipherAES)
	require.NoError(t, err, "generate AES-256 CBC KEK")
	t.Cleanup(func() { _ = kek.Delete() })

	hmac, err := testCtx.GenerateSecretKeyWithLabel(newKeyID(t), []byte(hmacLabel), 256, crypto11.CipherAES)
	require.NoError(t, err, "generate HMAC key")
	t.Cleanup(func() { _ = hmac.Delete() })

	sock := socketPath(t)
	t.Cleanup(func() { os.Remove(sock) })

	proc := startPlugin(t, sock,
		"--algorithm-family", string(providers.AlgAESCBC),
		"--p11-key-label",  kekLabel,
		"--p11-hmac-label", hmacLabel,
	)
	defer proc.stop()

	waitForSocket(t, sock)
	grpcRoundtrip(t, sock)
}

func TestPlugin_RSAOAEP(t *testing.T) {
	label := newLabel(t)

	kp, err := testCtx.GenerateRSAKeyPairWithLabel(newKeyID(t), []byte(label), 2048)
	require.NoError(t, err, "GenerateRSAKeyPairWithLabel 2048")
	t.Cleanup(func() { _ = kp.Delete() })

	sock := socketPath(t)
	t.Cleanup(func() { os.Remove(sock) })

	proc := startPlugin(t, sock,
		"--algorithm-family", string(providers.AlgRSAOAEP),
		"--p11-key-label", label,
	)
	defer proc.stop()

	waitForSocket(t, sock)
	grpcRoundtrip(t, sock)
}

// TestPlugin_MLKEM requires SoftHSMv3 (pqctoday-org/pqctoday-hsm).
// Automatically skipped on tokens that do not support CKM_ML_KEM_KEY_PAIR_GEN.
func TestPlugin_MLKEM(t *testing.T) {
	label := newLabel(t)

	kp, err := testCtx.GenerateMLKEMKeyPairWithLabel(newKeyID(t), []byte(label), crypto11.MLKEM768)
	if err != nil {
		t.Skipf("ML-KEM key generation not supported by this token: %v"+
			" — requires SoftHSMv3 from https://github.com/pqctoday-org/pqctoday-hsm", err)
	}
	t.Cleanup(func() { _ = kp.Delete() })

	sock := socketPath(t)
	t.Cleanup(func() { os.Remove(sock) })

	proc := startPlugin(t, sock,
		"--algorithm-family", string(providers.AlgMLKEM),
		"--p11-key-label", label,
	)
	defer proc.stop()

	waitForSocket(t, sock)
	grpcRoundtrip(t, sock)
}