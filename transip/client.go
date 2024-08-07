package transip

import (
	"bytes"
	"fmt"
	"strings"

	"k8s.io/klog"

	"github.com/transip/gotransip/v6"
	"github.com/transip/gotransip/v6/domain"

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

// NewClientinitializes a new TransIP client.
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

	return &Client{dnsRepo: domain.Repository{Client: client}}, nil
}

// getHostedDomain returns the hosted domain for the given zone.
func (c *Client) getHostedDomain(zone string) (string, error) {
	domainName := extractDomainName(zone)
	domain, err := c.dnsRepo.GetByDomainName(domainName)
	if err != nil {
		return "", fmt.Errorf("could net get domain %s: %w", domainName, err)
	}

	return domain.Name, nil
}

func (c *Client) setRecord(domainName, fqdn string, expire int, recordType string, Content string) error {

	dnsEntry := domain.DNSEntry{
		Name:    extractRecordName(fqdn, domainName),
		Expire:  expire,
		Type:    recordType,
		Content: Content,
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

func (c *Client) deleteRecord(domainName, fqdn string, expire int, recordType string, Content string) error {

	dnsEntry := domain.DNSEntry{
		Name:    extractRecordName(fqdn, domainName),
		Expire:  expire,
		Type:    recordType,
		Content: Content,
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

func extractRecordName(fqdn, domain string) string {
	if idx := strings.Index(fqdn, "."+domain); idx != -1 {
		return fqdn[:idx]
	}
	return util.UnFqdn(fqdn)
}
