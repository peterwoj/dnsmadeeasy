package dnsmadeeasy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Default API endpoints.
const (
	DefaultSandboxBaseURL = "https://api.sandbox.dnsmadeeasy.com/V2.0"
	DefaultProdBaseURL    = "https://api.dnsmadeeasy.com/V2.0"
)

type Client struct {
	apiKey    string
	apiSecret string

	BaseURL    *url.URL
	HTTPClient *http.Client
}

type Domain struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func NewClient(apiKey, apiSecret string) (*Client, error) {
	if "" == apiKey {
		return nil, errors.New("Missing credentials: API Key")
	}
	if "" == apiSecret {
		return nil, errors.New("Missing credentials: API Secret")
	}

	baseUrl, _ := url.Parse(DefaultProdBaseURL)

	return &Client{
		apiKey:    apiKey,
		apiSecret: apiSecret,
		BaseURL:   baseUrl,
		HTTPClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}, nil
}

func (c *Client) GetDomain(ctx context.Context, authZone string) (*Domain, error) {
	endpoint := c.BaseURL.JoinPath("dns", "managed", "name")
	domainName := authZone[0 : len(authZone)-1]

	query := endpoint.Query()
	query.Set("domainname", domainName)

	req, err := c.genNewRequest(ctx, endpoint, nil)
	if nil != err {
		return nil, err
	}

	domain := &Domain{}

	if err = c.doRequest(req, domain); nil != err {
		return nil, err
	}
	return domain, nil
}

func (c *Client) doRequest(req *http.Request, result any) error {
	resp, err := c.HTTPClient.Do(req)
	if nil != err {
		return errors.New(err.Error())
	}

	defer func() { _ = resp.Body.Close() }()

	if nil == result {
		return nil
	}

	raw, err := io.ReadAll(resp.Body)
	if nil != err {
		return errors.New(err.Error())
	}

	if err = json.Unmarshal(raw, result); nil != err {
		return errors.New(fmt.Sprintf("Unable to unmarshal response: %s", err.Error()))
	}

	return nil
}

func (c *Client) genNewRequest(ctx context.Context, endpoint *url.URL, payload any) (*http.Request, error) {
	buf := new(bytes.Buffer)

	if nil != payload {
		err := json.NewEncoder(buf).Encode(payload)
		if nil != err {
			return nil, fmt.Errorf("Failed to create request JSON body: %w", err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), buf)
	if nil != err {
		return nil, err
	}

	if nil != payload {
		req.Header.Set("Content-Type", "application/json")
	}

	// Sign the request
	timestamp := time.Now().UTC().Format(time.RFC1123)
	signature, err := c.genComputeHMAC(timestamp)
	if nil != err {
		return nil, err
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("x-dnsme-apiKey", c.apiKey)
	req.Header.Add("x-dnsme-hmac", signature)
	req.Header.Add("x-dnsme-requestDate", timestamp)

	return req, nil
}

func (c *Client) genComputeHMAC(timestamp string) (string, error) {
	key := []byte(c.apiSecret)
	hmacValue := hmac.New(sha1.New, key)
	_, err := hmacValue.Write([]byte(timestamp))
	if nil != err {
		return "", err
	}
	return hex.EncodeToString(hmacValue.Sum(nil)), nil
}
