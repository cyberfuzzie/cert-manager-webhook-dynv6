package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&customDNSProviderSolver{},
	)
}

// customDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
//
// It must implement the [webhook.Solver] interface:
// https://pkg.go.dev/github.com/cert-manager/cert-manager/pkg/acme/webhook#Solver
type customDNSProviderSolver struct {
	client *kubernetes.Clientset
}

var _ webhook.Solver = (*customDNSProviderSolver)(nil)

type Config struct {
	apiKey string
}

type ZonesResponse struct {
	Zones []Zone
}

type Zone struct {
	id int64
	name string
	ipv4address string
	ipv6prefix string
	createdAt string
	updatedAt string
}

type RecordsResponse struct {
	Records []Record
}

type Record struct {
	id int64
	zoneId int64
	name string
	Type string `json:"type"`
	priority int
	port int
	weight int
	flags int
	tag string
	data string
	expandedData string
}

// customDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type customDNSProviderConfig struct {
	APIKeySecretRef cmmeta.SecretKeySelector `json:"apiKeySecretRef"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *customDNSProviderSolver) Name() string {
	return "dynv6"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *customDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := c.init(ch.Config, ch.ResourceNamespace)
	if err != nil {
		return err
	}

	zone, err := getZone(cfg, ch.ResolvedFQDN)
	if err != nil {
		return err
	}

	name, found := strings.CutSuffix(ch.ResolvedFQDN, "." + zone.name)
	if !found {
		return fmt.Errorf("requested domain %q not in zone %q", ch.ResolvedFQDN, zone.name)
	}

	setRecordErr := setRecord(cfg, name, ch.Key, zone.id)

	return setRecordErr
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *customDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := c.init(ch.Config, ch.ResourceNamespace)
	if err != nil {
		return err
	}

	zone, err := getZone(cfg, ch.ResolvedFQDN)
	if err != nil {
		return err
	}

	record, ok := findRecord(cfg, zone.id, ch.Key)
	if !ok {
		return fmt.Errorf("No matching record found to cleanup")
	}

	delRecordErr := delRecord(cfg, zone.id, record.id)
	return delRecordErr
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *customDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}
	
	c.client = cl

	return nil
}

func (c *customDNSProviderSolver) init(cfgJSON *extapi.JSON, namespace string) (Config, error) {
	var config Config
	cfg, err := loadConfig(cfgJSON)
	if err != nil {
		return config, err
	}

	sec, err := c.client.CoreV1().Secrets(namespace).Get(context.TODO(), cfg.APIKeySecretRef.LocalObjectReference.Name, metav1.GetOptions{})
	if err != nil {
		return config, err
	}
	apiKey, ok := sec.Data["api-key"]
	if !ok {
		return config, fmt.Errorf("api-key not found in secret data")
	}

	config.apiKey = string(apiKey)
	return config, nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (customDNSProviderConfig, error) {
	cfg := customDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func getZone(config Config, fqdn string) (Zone, error) {
	result, err := dynv6Rest(config, "GET", "zones", "")
	if err != nil {
		return Zone{}, err
	}

	var zones ZonesResponse
	err = json.Unmarshal(result, &zones)
	if err != nil {
		return Zone{}, err
	}
	// TODO: support multiple zones
	return zones.Zones[0], nil
}

func findRecord(config Config, zoneId int64, content string) (Record, bool) {
	records, err := getRecords(config, zoneId)
	if err != nil {
		return Record{}, false
	}

	for _, record := range records.Records {
		if record.data == content {
			return record, true
		}
	}
	return Record{}, false
}

func getRecords(config Config, zoneId int64) (RecordsResponse, error) {
	result, err := dynv6Rest(config, "GET", fmt.Sprintf("zones/%d/records", zoneId), "")
	if err != nil {
		return RecordsResponse{}, err
	}

	var records RecordsResponse
	err = json.Unmarshal(result, &records)
	if err != nil {
		return RecordsResponse{}, err
	}
	return records, nil
}

func setRecord(config Config, name string, value string, zoneId int64) error {
	data := fmt.Sprintf(`{"value":%q, "type":"TXT", "name":%q}`, value, name)
	_, err := dynv6Rest(config, "POST", fmt.Sprintf("zones/%d/records", zoneId), data)
	return err
}

func delRecord(config Config, zoneId int64, recordId int64) error {
	_, err := dynv6Rest(config, "DELETE", fmt.Sprintf("zones/%d/records/%d", zoneId, recordId), "")
	return err
}

func dynv6Rest(config Config, method string, ep string, data string) ([]byte, error) {
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, method, fmt.Sprintf("https://dynv6.com/api/v2/%q", ep), bytes.NewBuffer([]byte(data)))
	if err != nil {
		return nil, fmt.Errorf("unable to execute request %v", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %q", config.apiKey))
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		err := resp.Body.Close()
		if err != nil {
			klog.Fatal(err)
		}
	}()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		return respBody, nil
	}

	text := "Error calling API status:" + resp.Status + " url: " + ep + " method: " + method
	klog.Error(text)
	return nil, errors.New(text)
}
