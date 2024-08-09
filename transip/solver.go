package transip

import (
	"context"
	"fmt"

	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	acme "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
)

func NewSolver() webhook.Solver {
	return &Solver{}
}

// Solver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type Solver struct {
	client *kubernetes.Clientset
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *Solver) Name() string {
	return "transip"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (s *Solver) Present(ch *acme.ChallengeRequest) error {
	klog.Infof("Presenting txt record: %v %v", ch.ResolvedFQDN, ch.ResolvedZone)

	cfg, err := loadConfig(ch.Config)
	if err != nil {
		klog.Errorf("Load config error: %v", err)
		return err
	}

	client, err := s.newClientFromChallenge(ch)
	if err != nil {
		klog.Errorf("New client from challenge error: %v", err)
		return err
	}

	domainName, err := client.getHostedDomain(ch.ResolvedZone)
	if err != nil {
		klog.Errorf("Get hosted zone %v error: %v", ch.ResolvedZone, err)
		return err
	}

	err = client.setRecord(domainName, ch.ResolvedFQDN, cfg.TTL, "TXT", ch.Key)
	if err != nil {
		klog.Errorf("Error while setting DNS entries for domain %s: %s\n", domainName, err)
		return err
	}

	klog.Infof("new txt record has been set : %v %v", ch.ResolvedFQDN, ch.ResolvedZone)

	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (s *Solver) CleanUp(ch *acme.ChallengeRequest) error {
	klog.Infof("Cleanup txt record: %v %v", ch.ResolvedFQDN, ch.ResolvedZone)

	cfg, err := loadConfig(ch.Config)
	if err != nil {
		klog.Errorf("Load config error: %v", err)
		return err
	}

	client, err := s.newClientFromChallenge(ch)
	if err != nil {
		klog.Errorf("New client from challenge error: %v", err)
		return err
	}

	domainName, err := client.getHostedDomain(ch.ResolvedZone)
	if err != nil {
		klog.Errorf("Get hosted zone %v error: %v", ch.ResolvedZone, err)
		return err
	}

	err = client.deleteRecord(domainName, ch.ResolvedFQDN, cfg.TTL, "TXT", ch.Key)
	if err != nil {
		klog.Errorf("Error while deleting DNS entries for domain %s: %s\n", domainName, err)
		return err
	}

	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initializing
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (s *Solver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	s.client = cl

	return nil
}

func (s *Solver) newClientFromChallenge(ch *acme.ChallengeRequest) (*Client, error) {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return nil, err
	}

	if klog.V(1).Enabled() {
		klog.Infof("Decoded config: %s", cfg)
	}

	clientCfg, err := s.getClientConfiguration(&cfg, ch.ResourceNamespace)
	if err != nil {
		return nil, fmt.Errorf("get credential error: %v", err)
	}

	client, err := newClient(clientCfg)
	if err != nil {
		return nil, fmt.Errorf("new dns client error: %v", err)
	}

	return client, nil
}

func (s *Solver) getClientConfiguration(cfg *Config, ns string) (ClientConfiguration, error) {
	var clientCfg ClientConfiguration
	if cfg.SecretRef.Name != "" {
		if cfg.SecretRef.Namespace != "" {
			ns = cfg.SecretRef.Namespace
		}
		accountName, err := s.getSecretData(ns, cfg.SecretRef.Name, "accountName")
		if err != nil {
			return ClientConfiguration{}, err
		}
		clientCfg.AccountName = string(accountName)

		privateKey, err := s.getSecretData(ns, cfg.SecretRef.Name, "privateKey")
		if err != nil {
			return ClientConfiguration{}, err
		}
		clientCfg.PrivateKey = privateKey
	} else {
		clientCfg.AccountName = cfg.AccountName
		if cfg.PrivateKeySecretRef.Name != "" {
			privateKey, err := s.getSecretData(ns, cfg.PrivateKeySecretRef.Name, cfg.PrivateKeySecretRef.Key)
			if err != nil {
				return ClientConfiguration{}, err
			}
			clientCfg.PrivateKey = privateKey
		} else {
			clientCfg.PrivateKey = cfg.PrivateKey
		}
	}

	clientCfg.DryRun = cfg.DryRun

	return clientCfg, nil
}

func (s *Solver) getSecretData(ns, name, key string) ([]byte, error) {
	secret, err := s.client.CoreV1().Secrets(ns).Get(context.TODO(), name, meta.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to load secret '%s/%s'", ns, name)
	}

	if data, ok := secret.Data[key]; ok {
		return data, nil
	}

	return nil, fmt.Errorf("key not found %q in secret '%s/%s'", key, ns, name)
}
