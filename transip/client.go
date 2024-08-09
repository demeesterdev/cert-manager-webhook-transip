package transip

import (
	"bytes"
	"fmt"
	"strings"

	"k8s.io/klog/v2"

	"github.com/transip/gotransip/v6"
	"github.com/transip/gotransip/v6/domain"
	"github.com/transip/gotransip/v6/test"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

type Client struct {
	dnsRepo domain.Repository
}

type ClientConfiguration struct {
	AccountName string
	PrivateKey  []byte
	DryRun      bool
}

// NewClient initializes a new TransIP client.
func newClient(cfg ClientConfiguration) (*Client, error) {
	var apiMode gotransip.APIMode
	if cfg.DryRun {
		apiMode = gotransip.APIModeReadOnly
	} else {
		apiMode = gotransip.APIModeReadWrite
	}

	// create new TransIP API client
	client, err := gotransip.NewClient(gotransip.ClientConfiguration{
		AccountName:      cfg.AccountName,
		PrivateKeyReader: bytes.NewReader(cfg.PrivateKey),
		Mode:             apiMode,
	})

	if err != nil {
		return nil, fmt.Errorf("could not setup TransIP API client: %w", err)
	}

	testClient := test.Repository{Client: client}
	err = testClient.Test()
	if err != nil {
		return nil, fmt.Errorf("test to connect with TransIP failed: %w", err)
	}

	return &Client{dnsRepo: domain.Repository{Client: client}}, nil
}

// getHostedDomain returns the hosted domain for the given zone.
func (c *Client) getHostedDomain(zone string) (string, error) {
	domainName := extractDomainName(zone)
	domainRef, err := c.dnsRepo.GetByDomainName(domainName)
	if err != nil {
		return "", fmt.Errorf("could net get domain %s: %w", domainName, err)
	}

	return domainRef.Name, nil
}

// setRecord creates a new DNS record in the given domain.
func (c *Client) setRecord(
	domainName, fqdn string, expire int, recordType, content string,
) error { //nolint: whitespace

	dnsEntry := domain.DNSEntry{
		Name:    extractRecordName(fqdn, domainName),
		Expire:  expire,
		Type:    recordType,
		Content: content,
	}

	dnsEntries, err := c.dnsRepo.GetDNSEntries(domainName)
	if err != nil {
		return err
	}

	for _, s := range dnsEntries {
		if s == dnsEntry {
			klog.Infof("ACME DNS entry %s already exists in domain %s, skip", dnsEntry.Name, domainName)
			return nil
		}
	}

	klog.Infof("Creating ACME DNS entry %v in domain %s", dnsEntry, domainName)

	err = c.dnsRepo.AddDNSEntry(domainName, dnsEntry)
	if err != nil {
		return fmt.Errorf("could not add DNS record: %w", err)
	}

	return nil
}

// deleteRecord deletes a DNS record in the given domain.
func (c *Client) deleteRecord(
	domainName, fqdn string, expire int, recordType, content string,
) error { //nolint: whitespace

	dnsEntry := domain.DNSEntry{
		Name:    extractRecordName(fqdn, domainName),
		Expire:  expire,
		Type:    recordType,
		Content: content,
	}

	dnsEntries, err := c.dnsRepo.GetDNSEntries(domainName)
	if err != nil {
		return err
	}

	for _, s := range dnsEntries {
		if s == dnsEntry {
			err = c.dnsRepo.RemoveDNSEntry(domainName, dnsEntry)
			if err != nil {
				return err
			}
			return nil
		}
	}

	klog.Infof("ACME DNS entry not found matching %v ", dnsEntry)

	return nil
}

func extractDomainName(zone string) string {
	authZone, err := util.FindZoneByFqdn(zone, util.RecursiveNameservers)

	if err != nil {
		fmt.Printf("could not get zone by fqdn %v", err)
		return zone
	}
	return util.UnFqdn(authZone)
}

func extractRecordName(fqdn, domainName string) string {
	if idx := strings.Index(fqdn, "."+domainName); idx != -1 {
		return fqdn[:idx]
	}
	return util.UnFqdn(fqdn)
}
