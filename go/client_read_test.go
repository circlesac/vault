package vault

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func jwkNumber(value *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(value.Bytes())
}

func TestReadSendsInstallationIDOnEveryDataRequest(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	device := &DeviceKey{
		ClientID: "test-installation-id",
		PrivateKey: map[string]any{
			"n": jwkNumber(privateKey.N),
			"e": jwkNumber(big.NewInt(int64(privateKey.E))),
			"d": jwkNumber(privateKey.D),
			"p": jwkNumber(privateKey.Primes[0]),
			"q": jwkNumber(privateKey.Primes[1]),
		},
	}
	accountKey := make([]byte, 32)
	if _, err := rand.Read(accountKey); err != nil {
		t.Fatal(err)
	}
	wrappedAccountKey, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		&privateKey.PublicKey,
		accountKey,
		[]byte("cvlt:v1:account:user:1"),
	)
	if err != nil {
		t.Fatal(err)
	}

	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		paths = append(paths, request.URL.Path)
		if got := request.Header.Get("X-CVLT-Client-ID"); got != device.ClientID {
			http.Error(response, "missing installation id", http.StatusForbidden)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/status":
			_ = json.NewEncoder(response).Encode(map[string]any{
				"account":     "user:1",
				"initialized": true,
				"client": map[string]any{
					"id": device.ClientID,
					"wrapped_account_key": map[string]any{
						"version":    1,
						"algorithm":  "RSA-OAEP-3072-SHA256",
						"ciphertext": base64.RawURLEncoding.EncodeToString(wrappedAccountKey),
					},
				},
			})
		case "/v1/vaults":
			_ = json.NewEncoder(response).Encode([]map[string]any{{
				"id":           "vault-id",
				"content_mode": "plain",
				"name":         "example-vault",
			}})
		case "/v1/vaults/vault-id/items/resolve":
			_ = json.NewEncoder(response).Encode(map[string]any{
				"id":           "item-id",
				"vault_id":     "vault-id",
				"content_mode": "plain",
				"fields": []map[string]any{{
					"id":      "password",
					"label":   "password",
					"value":   "test-secret",
					"type":    "CONCEALED",
					"purpose": "PASSWORD",
				}},
			})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	client := &Client{
		baseURL:       server.URL,
		token:         "test-token",
		httpClient:    server.Client(),
		loadDeviceKey: func(string) (*DeviceKey, error) { return device, nil },
	}
	value, err := client.Read(context.Background(), "op://example-vault/example-item/password")
	if err != nil {
		t.Fatal(err)
	}
	if value != "test-secret" {
		t.Fatalf("got %q, want test-secret", value)
	}
	wantPaths := []string{
		"/v1/status",
		"/v1/vaults",
		"/v1/vaults/vault-id/items/resolve",
	}
	if !reflect.DeepEqual(paths, wantPaths) {
		t.Fatalf("got paths %v, want %v", paths, wantPaths)
	}
}
