package transip

import (
	"encoding/json"
	"errors"
	"fmt"

	core "k8s.io/api/core/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

// Config is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
type Config struct {
	SecretRef           core.SecretReference   `json:"secretRef"`
	AccountName         string                 `json:"accountName"`
	PrivateKey          []byte                 `json:"privateKey"`
	PrivateKeySecretRef core.SecretKeySelector `json:"privateKeySecretRef"`
	TTL                 int                    `json:"ttl"`
	DryRun              bool                   `json:"dryRun"`
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (Config, error) {
	cfg := Config{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	if err := validateConfig(&cfg); err != nil {
		return cfg, fmt.Errorf("error validating solver config: %v", err)
	}

	return cfg, nil
}

// validateConfigchecks the configuration to ensure it is valid.
func validateConfig(cfg *Config) error {
	if cfg.AccountName == "" {
		return errors.New("accountName is required")
	}
	if cfg.SecretRef.Name == "" && len(cfg.PrivateKey) == 0 && cfg.PrivateKeySecretRef.Name == "" {
		return errors.New("secretRef, privateKey or privateKeySecretRef is required")
	}
	if len(cfg.PrivateKey) != 0 && cfg.PrivateKeySecretRef.Name != "" {
		return errors.New("only one of privateKey or privateKeySecretRef can be set")
	}
	if len(cfg.PrivateKey) != 0 && cfg.SecretRef.Name != "" {
		return errors.New("only one of privateKey or secretRef can be set")
	}
	if cfg.SecretRef.Name != "" && cfg.PrivateKeySecretRef.Name != "" {
		return errors.New("only one of secretRef or privateKeySecretRef can be set")
	}
	if cfg.SecretRef.Name == "" && cfg.AccountName == "" {
		return errors.New("secretRef, or accountName is required")
	}
	if cfg.TTL < 0 {
		return errors.New("ttl must be greater than or equal to 0")
	}
	return nil
}

func (c Config) String() string {
	if len(c.PrivateKey) != 0 {
		return fmt.Sprintf(
			"{secretRef: %v, accountName: %s, privateKey: <****>, privateKeySecretRef: %v, ttl: %d, dryRun: %t}",
			c.SecretRef,
			c.AccountName,
			c.PrivateKeySecretRef,
			c.TTL,
			c.DryRun)
	}
	return fmt.Sprintf("{secretRef: %v, accountName: %s, privateKey: nil, privateKeySecretRef: %v, ttl: %d, dryRun: %t}",
		c.SecretRef,
		c.AccountName,
		c.PrivateKeySecretRef,
		c.TTL,
		c.DryRun)
}
