# ACME webhook for TransIP API

This is an implementation of a Cert-Manager webhook for implementing DNS01 acme verification with TransIP as a DNS provider.

## Requirements

- [go](https://golang.org/) >= 1.13.0
- [helm](https://helm.sh/) >= v3.0.0
- [kubernetes](https://kubernetes.io/) >= v1.14.0
- [cert-manager](https://cert-manager.io/) >= 0.12.0

## Installation

### cert-manager

Follow the [instructions](https://cert-manager.io/docs/installation/) using the cert-manager documentation to install it within your cluster.

### Webhook

#### Using public helm chart

```bash
helm repo add cert-manager-webhook-transip https://demeester.dev/cert-manager-webhook-transip
# Replace the groupName value with your desired domain
helm install --namespace cert-manager cert-manager-webhook-transip cert-manager-webhook-transip/cert-manager-webhook-transip
```

#### From local checkout

```bash
helm install --namespace cert-manager cert-manager-webhook-transip charts/cert-manager-webhook-transip
```

**Note**: The kubernetes resources used to install the Webhook should be deployed within the same namespace as the cert-manager.

To uninstall the webhook run

```bash
helm uninstall --namespace cert-manager cert-manager-webhook-transip
```

## Issuer

Create a `ClusterIssuer` or `Issuer` resource as following:
(Keep in Mind that the Example uses the Staging URL from Let's Encrypt. Look at [Getting Start](https://letsencrypt.org/getting-started/) for using the normal Let's Encrypt URL.)

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-staging
spec:
  acme:
    # The ACME server URL
    server: https://acme-staging-v02.api.letsencrypt.org/directory

    # Email address used for ACME registration
    email: mail@example.com # REPLACE THIS WITH YOUR EMAIL!!!

    # Name of a secret used to store the ACME account private key
    privateKeySecretRef:
      name: letsencrypt-staging

    solvers:
      - dns01:
          webhook:
            groupName: acme.transip.nl
            solverName: transip
            config:
              accountName: your-transip-username
              ttl: 300
              privateKeySecretRef:
                name: transip-secret
                key: privateKey
```

### Credentials

In order to access the TransIP API, the webhook needs an API token in te form of a private key.
You can generate a key pair using the [control panel](https://www.transip.nl/cp/account/api/)

If you choose another name for the secret than `transip-secret`, you must install the chart with a modified `secretName` value. Policies ensure that no other secrets can be read by the webhook. Also modify the value of `secretName` in the `[Cluster]Issuer`.

you can create the secret from filename

```bash
kubectl -n cert-manager create secret generic transip-credentials --from-file=privateKey
```

The secret for the example above will look like this:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: transip-secret
  namespace: cert-manager
type: Opaque
data:
  privateKey: your-key-base64-encoded
```

### Create a certificate

Finally you can create certificates, for example:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-cert
  namespace: cert-manager
spec:
  commonName: example.com
  dnsNames:
    - example.com
  issuerRef:
    name: letsencrypt-staging
    kind: ClusterIssuer
  secretName: example-cert
```

## Development

### Running the test suite

All DNS providers **must** run the DNS01 provider conformance testing suite,
else they will have undetermined behaviour when used with cert-manager.

**It is essential that you configure and run the test suite when creating a
DNS01 webhook.**

First, you need to have an Transip account with a domain name regisred to it. next to an account you also need to generate an api token for it.
Then you need to replace the parameters `accountName` and `privateKey` at `testdata/cert-manager-webhook-transip/config.json` file with actual ones.

You can then run the test suite with:

```bash
# then run the tests
TEST_ZONE_NAME=example.com. make test
```

## Creating new package

To build new Docker image for multiple architectures and push it to hub:

```shell
docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 -t demeesterdev/cert-manager-webhook-transip:1.2.0 . --push
```

To compile and publish new Helm chart version:

```shell
helm package charts/cert-manager-webhook-transip
git checkout gh-pages
helm repo index . --url https://demeester.dev/cert-manager-webhook-transip/
```
