package dnsmadeeasy

import (
	"context"
	"github.com/libdns/libdns"
	"slices"
	"strconv"
	"time"
)

// Provider facilitates DNS record manipulation with <TODO: PROVIDER NAME>.
type Provider struct {
	APIUrlBase string `json:"dnsme_api_url"`
	APIKey     string `json:"dnsme_apikey"`
	APISecret  string `json:"dnsme_secret"`
	client     *Client
}

func (p *Provider) getClient() error {
	if nil == p.client {
		client, err := NewClient(p.APIKey, p.APISecret)
		if nil != err {
			return err
		}
		p.client = client
	}
	return nil
}

func (p *Provider) getClientAndDomain(ctx context.Context, zone string) (*Domain, error) {
	if err := p.getClient(); nil != err {
		return nil, err
	}
	domain, err := p.client.GetDomain(ctx, zone)
	if nil != err {
		return nil, err
	}
	return domain, nil

}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	domain, err := p.getClientAndDomain(ctx, zone)
	if nil != err {
		return nil, err
	}

	records, err := p.client.GetRecords(ctx, domain, nil, nil)
	if nil != err {
		return nil, err
	}

	var libRecords []libdns.Record
	for _, record := range *records {
		libRecords = append(libRecords, libdns.Record{
			ID:       strconv.Itoa(record.ID),
			Type:     record.Type,
			Name:     record.Name,
			Value:    record.Value,
			TTL:      time.Duration(record.TTL * int(time.Second)),
			Priority: record.Priority,
		})
	}

	return libRecords, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	domain, err := p.getClientAndDomain(ctx, zone)
	if nil != err {
		return nil, err
	}
	zoneRecords, err := p.client.GetRecords(ctx, domain, nil, nil)
	if nil != err {
		return nil, err
	}

	appendRecords := &[]Record{}
	var appendLibDnsRecords []libdns.Record
	for _, record := range records {
		if idxFound := slices.IndexFunc(*zoneRecords, func(r Record) bool {
			return r.Type == record.Type && r.Name == record.Name
		}); idxFound == -1 {
			*appendRecords = append(*appendRecords, Record{
				Type:        record.Type,
				Name:        record.Name,
				Value:       record.Value,
				TTL:         int(record.TTL.Seconds()),
				Priority:    record.Priority,
				GtdLocation: "DEFAULT",
			})
			appendLibDnsRecords = append(appendLibDnsRecords, record)
		}
	}

	return appendLibDnsRecords, p.client.GenCreateRecords(ctx, domain, &Records{Records: appendRecords})
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	domain, err := p.getClientAndDomain(ctx, zone)
	if nil != err {
		return nil, err
	}

	zoneRecords, err := p.client.GetRecords(ctx, domain, nil, nil)
	if nil != err {
		return nil, err
	}

	var newRecords []Record
	var updRecords []Record
	var updatedRecords []libdns.Record

	for _, record := range records {
		if idxFound := slices.IndexFunc(*zoneRecords, func(r Record) bool {
			return r.Type == record.Type && r.Name == record.Name
		}); idxFound == -1 {
			newRecords = append(newRecords, Record{
				Type:        record.Type,
				Name:        record.Name,
				Value:       record.Value,
				TTL:         int(record.TTL.Seconds()),
				Priority:    record.Priority,
				GtdLocation: "DEFAULT",
			})
		} else {
			updRecords = append(updRecords, Record{
				ID:          (*zoneRecords)[idxFound].ID,
				Type:        record.Type,
				Name:        record.Name,
				Value:       record.Value,
				TTL:         int(record.TTL.Seconds()),
				Priority:    record.Priority,
				GtdLocation: "DEFAULT",
			})
			updatedRecords = append(updatedRecords, record)
		}
	}

	err = p.client.GenCreateRecords(ctx, domain, &Records{Records: &newRecords})
	if nil != err {
		return nil, err
	}

	err = p.client.GenUpdateRecords(ctx, domain, &Records{Records: &updRecords})
	if nil != err {
		return nil, err
	}

	return updatedRecords, nil
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	domain, err := p.getClientAndDomain(ctx, zone)
	if nil != err {
		return nil, err
	}

	zoneRecords, err := p.client.GetRecords(ctx, domain, nil, nil)
	if nil != err {
		return nil, err
	}

	var dRecs []Record
	for _, record := range records {
		if idxFound := slices.IndexFunc(*zoneRecords, func(r Record) bool {
			return r.Type == record.Type && r.Name == record.Name
		}); idxFound >= 0 {
			dRecs = append(dRecs, Record{
				ID: (*zoneRecords)[idxFound].ID,
			})
		}
	}

	return records, p.client.GenDeleteRecords(ctx, domain, &Records{Records: &dRecs})
}

var (
	_ libdns.RecordGetter
	_ libdns.RecordAppender
	_ libdns.RecordSetter
	_ libdns.RecordDeleter
)
