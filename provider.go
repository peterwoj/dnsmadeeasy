package dnsmadeeasy

import (
	"context"

	"log"
)

type Provider struct {
	APIUrlBase string `json:"api_url"`
	APIKey     string `json:"dnsme_apikey"`
	APISecret  string `json:"dnsme_secret"`
}

func main() {
	apiKey := ""
	apiSecret := ""
	client, err := NewClient(apiKey, apiSecret)
	if nil != err {
		log.Printf("Error creating a new client: %s\n", err)
	}
	domain, err := client.GetDomain(context.Background(), "wojstead.com")

	log.Printf("domain: %s\n", domain.Name)
}

//var (
//	_ libdns.RecordGetter
//	_ libdns.RecordAppender
//	_ libdns.RecordSetter
//	_ libdns.RecordDeleter
//)
