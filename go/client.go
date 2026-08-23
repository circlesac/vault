package vault

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"

	credentials "github.com/circlesac/credentials/go"
	"golang.org/x/text/unicode/norm"
)

type Client struct {
	baseURL, token string
	httpClient     *http.Client
	loadDeviceKey  func(string) (*DeviceKey, error)
}
type rsaEnvelope struct {
	Version               int `json:"version"`
	Algorithm, Ciphertext string
}
type statusResponse struct {
	Account     string
	Initialized bool
	Client      *struct {
		ID      string      `json:"id"`
		Wrapped rsaEnvelope `json:"wrapped_account_key"`
	} `json:"client"`
}
type vaultRow struct {
	ID          string           `json:"id"`
	ContentMode string           `json:"content_mode"`
	Name        string           `json:"name"`
	Overview    *ContentEnvelope `json:"overview"`
	Wrapped     *AESEnvelope     `json:"wrapped_vault_key"`
}
type itemRow struct {
	ID          string           `json:"id"`
	VaultID     string           `json:"vault_id"`
	ContentMode string           `json:"content_mode"`
	Fields      []field          `json:"fields"`
	Overview    *ContentEnvelope `json:"overview"`
	Details     *ContentEnvelope `json:"details"`
}
type field struct{ ID, Label, Value, Type, Purpose string }
type vaultOverview struct{ Name string }
type itemOverview struct{ Title string }
type itemDetails struct{ Fields []field }

func NewClient(ctx context.Context) (*Client, error) {
	if host, token := os.Getenv("OP_CONNECT_HOST"), os.Getenv("OP_CONNECT_TOKEN"); host != "" && token != "" {
		return &Client{strings.TrimRight(host, "/"), token, http.DefaultClient, LoadDeviceKey}, nil
	}
	provider, err := credentials.New()
	if err != nil {
		return nil, err
	}
	credential, err := provider.Resolve(ctx)
	if err != nil {
		return nil, err
	}
	return &Client{"https://vault.circles.ac", credential.Value, http.DefaultClient, LoadDeviceKey}, nil
}

func (client *Client) request(ctx context.Context, method, path string, body any, target any, device *DeviceKey) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = strings.NewReader(string(encoded))
	}
	req, err := http.NewRequestWithContext(ctx, method, client.baseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+client.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if device != nil {
		req.Header.Set("X-CVLT-Client-ID", device.ClientID)
	}
	res, err := client.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		message, _ := io.ReadAll(res.Body)
		return fmt.Errorf("Vault API %d: %s", res.StatusCode, strings.TrimSpace(string(message)))
	}
	return json.NewDecoder(res.Body).Decode(target)
}

func jwkInteger(value any) (*big.Int, error) {
	text, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("invalid JWK")
	}
	data, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(data), nil
}
func privateRSA(jwk map[string]any) (*rsa.PrivateKey, error) {
	n, err := jwkInteger(jwk["n"])
	if err != nil {
		return nil, err
	}
	d, err := jwkInteger(jwk["d"])
	if err != nil {
		return nil, err
	}
	p, err := jwkInteger(jwk["p"])
	if err != nil {
		return nil, err
	}
	q, err := jwkInteger(jwk["q"])
	if err != nil {
		return nil, err
	}
	eBig, err := jwkInteger(jwk["e"])
	if err != nil {
		return nil, err
	}
	key := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: n, E: int(eBig.Int64())}, D: d, Primes: []*big.Int{p, q}}
	if err := key.Validate(); err != nil {
		return nil, err
	}
	key.Precompute()
	return key, nil
}
func unwrapAccount(envelope rsaEnvelope, jwk map[string]any, account string) ([]byte, error) {
	key, err := privateRSA(jwk)
	if err != nil {
		return nil, err
	}
	data, err := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, key, data, []byte("cvlt:v1:account:"+account))
}
func locator(key []byte, title string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("cvlt:v1:locator\x00" + norm.NFKC.String(title)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (client *Client) Read(ctx context.Context, reference string) (string, error) {
	ref, err := ParseReference(reference)
	if err != nil {
		return "", err
	}
	if ref.Scheme != "op" {
		return "", fmt.Errorf("vlt references are not supported yet")
	}
	origin := client.baseURL
	if index := strings.Index(origin[8:], "/"); index >= 0 {
		origin = origin[:8+index]
	}
	loadDeviceKey := client.loadDeviceKey
	if loadDeviceKey == nil {
		loadDeviceKey = LoadDeviceKey
	}
	device, err := loadDeviceKey(origin)
	if err != nil {
		return "", err
	}
	if device == nil {
		return "", fmt.Errorf("Vault device key not found")
	}
	var status statusResponse
	if err := client.request(ctx, "GET", "/v1/status", nil, &status, device); err != nil {
		return "", err
	}
	if status.Client == nil {
		return "", fmt.Errorf("Vault device is not registered")
	}
	accountKey, err := unwrapAccount(status.Client.Wrapped, device.PrivateKey, status.Account)
	if err != nil {
		return "", err
	}
	// Data routes carry the installation identity too: the service rechecks it
	// against the account on every request, so a revoked installation stops
	// reading even while this process still holds the unwrapped account key.
	var vaults []vaultRow
	if err := client.request(ctx, "GET", "/v1/vaults", nil, &vaults, device); err != nil {
		return "", err
	}
	var selected *vaultRow
	var vaultKey []byte
	for index := range vaults {
		row := &vaults[index]
		if row.ContentMode == "plain" && strings.EqualFold(row.Name, ref.Vault) {
			selected = row
			break
		}
		if row.Wrapped == nil || row.Overview == nil {
			continue
		}
		key, err := unwrapKey(*row.Wrapped, accountKey, "cvlt:v1:account:"+status.Account+":vault:"+row.ID)
		if err != nil {
			continue
		}
		plain, err := DecryptContent(*row.Overview, key, "cvlt:v1:vault:"+row.ID+":overview")
		if err != nil {
			continue
		}
		var overview vaultOverview
		if json.Unmarshal(plain, &overview) == nil && strings.EqualFold(overview.Name, ref.Vault) {
			selected = row
			vaultKey = key
			break
		}
	}
	if selected == nil {
		return "", fmt.Errorf("vault %q not found", ref.Vault)
	}
	var item itemRow
	if err := client.request(ctx, "POST", "/v1/vaults/"+selected.ID+"/items/resolve", map[string]string{"locator": locator(vaultKey, ref.Item)}, &item, device); err != nil {
		return "", err
	}
	if item.ContentMode != "plain" {
		if item.Details == nil {
			return "", fmt.Errorf("item details missing")
		}
		plain, err := DecryptContent(*item.Details, vaultKey, "cvlt:v1:vault:"+selected.ID+":item:"+item.ID+":details")
		if err != nil {
			return "", err
		}
		var details itemDetails
		if err := json.Unmarshal(plain, &details); err != nil {
			return "", err
		}
		item.Fields = details.Fields
	}
	for _, candidate := range item.Fields {
		if candidate.Label == ref.Field || candidate.ID == ref.Field || strings.EqualFold(candidate.Purpose, ref.Field) {
			return candidate.Value, nil
		}
	}
	return "", fmt.Errorf("field %q not found", ref.Field)
}
