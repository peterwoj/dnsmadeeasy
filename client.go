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
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
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

type Record struct {
	ID          int    `json:"id"`
	Type        string `json:"type"`
	Name        string `json:"name"`
	Value       string `json:"value"`
	TTL         int    `json:"ttl"`
	Priority    int    `json:"mxLevel"`
	SourceID    int    `json:"sourceId"`
	GtdLocation string `json:"gtdLocation"`
}

type Records struct {
	TotalPages   int       `json:"totalPages"`
	TotalRecords int       `json:"totalRecords"`
	Page         int       `json:"page"`
	Records      *[]Record `json:"data"`
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

func (c *Client) GetDomain(ctx context.Context, zone string) (*Domain, error) {
	endpoint := c.BaseURL.JoinPath("dns", "managed", "name")
	domainName := strings.TrimRight(zone, ".")

	query := endpoint.Query()
	query.Set("domainname", domainName)
	endpoint.RawQuery = query.Encode()

	req, err := c.genNewRequest(ctx, http.MethodGet, endpoint, nil)
	if nil != err {
		return nil, err
	}

	domain := &Domain{}

	if err = c.genDoRequest(req, domain); nil != err {
		return nil, err
	}
	return domain, nil
}

func (c *Client) GetRecords(ctx context.Context, domain *Domain, recordName, recordType *string) (*[]Record, error) {
	endpoint := c.BaseURL.JoinPath("dns", "managed", strconv.Itoa(domain.ID), "records")

	query := endpoint.Query()
	if nil != recordName {
		query.Set("recordName", *recordName)
	}
	if nil != recordType {
		query.Set("type", *recordType)
	}
	if nil != recordName || nil != recordType {
		endpoint.RawQuery = query.Encode()
	}

	req, err := c.genNewRequest(ctx, http.MethodGet, endpoint, nil)
	if nil != err {
		return nil, err
	}

	records := &Records{}
	err = c.genDoRequest(req, records)
	if nil != err {
		return nil, err
	}
	return records.Records, nil
}

func (c *Client) GenCreateRecord(ctx context.Context, domain *Domain, record *Record) error {
	endpoint := c.BaseURL.JoinPath("dns", "managed", strconv.Itoa(domain.ID), "records")

	req, err := c.genNewRequest(ctx, http.MethodPost, endpoint, record)
	if nil != err {
		return err
	}

	return c.genDoRequest(req, nil)
}

func (c *Client) GenCreateRecords(ctx context.Context, domain *Domain, records *Records) error {
	endpoint := c.BaseURL.JoinPath("dns", "managed", strconv.Itoa(domain.ID), "records", "createMulti")

	req, err := c.genNewRequest(ctx, http.MethodPost, endpoint, records.Records)
	if nil != err {
		return err
	}

	return c.genDoRequest(req, nil)
}

func (c *Client) GenUpdateRecords(ctx context.Context, domain *Domain, records *Records) error {
	endpoint := c.BaseURL.JoinPath("dns", "managed", strconv.Itoa(domain.ID), "records", "updateMulti")

	req, err := c.genNewRequest(ctx, http.MethodPut, endpoint, records.Records)
	if nil != err {
		return err
	}

	return c.genDoRequest(req, nil)
}

func (c *Client) GenDeleteRecord(ctx context.Context, domain *Domain, record *Record) error {
	endpoint := c.BaseURL.JoinPath("dns", "managed", strconv.Itoa(domain.ID), "records", strconv.Itoa(record.ID))

	req, err := c.genNewRequest(ctx, http.MethodDelete, endpoint, nil)
	if nil != err {
		return err
	}

	return c.genDoRequest(req, nil)
}

func (c *Client) GenDeleteRecords(ctx context.Context, domain *Domain, records *Records) error {
	endpoint := c.BaseURL.JoinPath("dns", "managed", strconv.Itoa(domain.ID), "records")

	query := endpoint.Query()
	for _, record := range *records.Records {
		query.Add("ids", strconv.Itoa(record.ID))
	}
	endpoint.RawQuery = query.Encode()

	req, err := c.genNewRequest(ctx, http.MethodDelete, endpoint, nil)
	if nil != err {
		return err
	}
	return c.genDoRequest(req, nil)
}

func (c *Client) genDoRequest(req *http.Request, result any) error {
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
		log.Printf("response was: %s\n", raw)
		return errors.New(fmt.Sprintf("Unable to unmarshal response: %s", err.Error()))
	}

	return nil
}

func (c *Client) genNewRequest(ctx context.Context, httpMethod string, endpoint *url.URL, payload any) (*http.Request, error) {
	buf := new(bytes.Buffer)

	if nil != payload {
		err := json.NewEncoder(buf).Encode(payload)
		if nil != err {
			return nil, fmt.Errorf("Failed to create request JSON body: %w", err)
		}
	}

	//log.Printf("endpoing: %s\n", endpoint.String())
	//log.Printf("have buf: %s\n", buf)

	req, err := http.NewRequestWithContext(ctx, httpMethod, endpoint.String(), buf)
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
