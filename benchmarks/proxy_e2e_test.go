//go:build benchmark

package benchmarks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rakeshguha/redactr/internal/certgen"
	"github.com/rakeshguha/redactr/internal/coordinator"
	"github.com/rakeshguha/redactr/internal/domain"
	"github.com/rakeshguha/redactr/internal/fileblock"
	"github.com/rakeshguha/redactr/internal/proxy"
	"github.com/rakeshguha/redactr/internal/scanner"
	"github.com/rakeshguha/redactr/internal/scanner/contextgate"
	"github.com/rakeshguha/redactr/internal/scanner/entropy"
	"github.com/rakeshguha/redactr/internal/scanner/gliner"
	"github.com/rakeshguha/redactr/internal/scanner/opf"
	"github.com/rakeshguha/redactr/internal/scanner/presidio"
	"github.com/rakeshguha/redactr/internal/sidecar"
	"github.com/rakeshguha/redactr/internal/store"
)

type piiEntry struct {
	Value json.RawMessage `json:"value"`
	Start int             `json:"start"`
	End   int             `json:"end"`
	Label string          `json:"label"`
}

func (p piiEntry) ValueString() string {
	s := string(p.Value)
	if len(s) >= 2 && s[0] == '"' {
		var unq string
		json.Unmarshal(p.Value, &unq)
		return unq
	}
	return s
}

type benchSample struct {
	ID     string     `json:"id"`
	Text   string     `json:"text"`
	Locale string     `json:"locale"`
	Domain string     `json:"domain"`
	PII    []piiEntry `json:"pii"`
}

type benchConfig struct {
	datasetName      string
	dataFile         string
	detectableLabels map[string]bool
	ignoredLabels    map[string]bool
	pipelineMode     string // "default", "opf_first", "gliner_first"
}

func findSidecarScript() string {
	candidates := []string{}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(wd, "sidecar", "gliner", "server.py"))
		candidates = append(candidates, filepath.Join(wd, "..", "sidecar", "gliner", "server.py"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".redactr", "..", "sidecar", "gliner", "server.py"))
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

func setupGLiNER(t *testing.T) (*gliner.Client, func()) {
	t.Helper()
	noop := func() {}

	// 1. Try existing sidecar via port file
	if home, err := os.UserHomeDir(); err == nil {
		if portBytes, err := os.ReadFile(filepath.Join(home, ".redactr", "state", "sidecar.port")); err == nil {
			port := strings.TrimSpace(string(portBytes))
			client := gliner.New("http://127.0.0.1:" + port)
			for i := 0; i < 5; i++ {
				if client.HealthCheck() {
					client.SetReady(true)
					t.Logf("GLiNER sidecar connected on port %s", port)
					return client, noop
				}
				time.Sleep(500 * time.Millisecond)
			}
			t.Log("Stale sidecar port file — sidecar not responding")
		}
	}

	// 2. Start our own sidecar
	script := findSidecarScript()
	if script == "" {
		t.Log("WARNING: GLiNER sidecar script not found — running without GLiNER")
		return gliner.New("http://127.0.0.1:0"), noop
	}

	port, err := sidecar.FindFreePort()
	if err != nil {
		t.Logf("WARNING: could not find free port for sidecar: %v", err)
		return gliner.New("http://127.0.0.1:0"), noop
	}

	cmd := exec.Command("python3", script, fmt.Sprintf("%d", port))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Logf("WARNING: could not start GLiNER sidecar: %v", err)
		return gliner.New("http://127.0.0.1:0"), noop
	}

	cleanup := func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}

	t.Logf("Started GLiNER sidecar on port %d — waiting for model load...", port)
	client := gliner.New(fmt.Sprintf("http://127.0.0.1:%d", port))

	ready := false
	for i := 0; i < 180; i++ {
		if client.HealthCheck() {
			client.SetReady(true)
			ready = true
			t.Logf("GLiNER sidecar ready after %ds", i)
			break
		}
		time.Sleep(1 * time.Second)
	}

	if !ready {
		t.Log("WARNING: GLiNER sidecar failed to become ready within 3 minutes")
		cleanup()
		return gliner.New("http://127.0.0.1:0"), noop
	}

	return client, cleanup
}

func findOPFSidecarScript() string {
	candidates := []string{}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(wd, "sidecar", "opf", "server.py"))
		candidates = append(candidates, filepath.Join(wd, "..", "sidecar", "opf", "server.py"))
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

func setupOPF(t *testing.T) (*opf.Client, func()) {
	t.Helper()
	noop := func() {}

	script := findOPFSidecarScript()
	if script == "" {
		t.Log("WARNING: OPF sidecar script not found — running without OPF")
		return opf.New("http://127.0.0.1:0"), noop
	}

	port, err := sidecar.FindFreePort()
	if err != nil {
		t.Logf("WARNING: could not find free port for OPF sidecar: %v", err)
		return opf.New("http://127.0.0.1:0"), noop
	}

	cmd := exec.Command("python3", script, fmt.Sprintf("%d", port))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Logf("WARNING: could not start OPF sidecar: %v", err)
		return opf.New("http://127.0.0.1:0"), noop
	}

	cleanup := func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}

	t.Logf("Started OPF sidecar on port %d — waiting for model load...", port)
	client := opf.New(fmt.Sprintf("http://127.0.0.1:%d", port))

	ready := false
	for i := 0; i < 180; i++ {
		if client.HealthCheck() {
			client.SetReady(true)
			ready = true
			t.Logf("OPF sidecar ready after %ds", i)
			break
		}
		time.Sleep(1 * time.Second)
	}

	if !ready {
		t.Log("WARNING: OPF sidecar failed to become ready within 3 minutes")
		cleanup()
		return opf.New("http://127.0.0.1:0"), noop
	}

	return client, cleanup
}

func loadBenchSamples(t *testing.T, path string) []benchSample {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("load samples: %v", err)
	}
	var samples []benchSample
	if err := json.Unmarshal(data, &samples); err != nil {
		t.Fatalf("parse samples: %v", err)
	}
	return samples
}

func TestNemotronBenchmark(t *testing.T) {
	runBenchmark(t, benchConfig{
		datasetName: "nvidia/Nemotron-PII",
		dataFile:    "testdata/nemotron_pii_samples.json",
		detectableLabels: map[string]bool{
			"email": true, "ssn": true, "credit_debit_card": true, "phone_number": true,
			"fax_number": true, "ipv4": true, "mac_address": true, "url": true,
			"password": true, "pin": true, "cvv": true, "user_name": true,
			"account_number": true, "bank_routing_number": true, "swift_bic": true,
			"customer_id": true, "employee_id": true, "medical_record_number": true,
			"certificate_license_number": true, "license_plate": true,
			"vehicle_identifier": true, "device_identifier": true,
			"http_cookie": true, "biometric_identifier": true,
			"health_plan_beneficiary_number": true, "postcode": true,
		},
		ignoredLabels: map[string]bool{
			"date": true, "date_time": true, "company_name": true,
			"occupation": true, "gender": true, "blood_type": true,
			"religious_belief": true, "country": true, "state": true, "county": true,
			"education_level": true, "time": true, "age": true, "language": true,
			"sexuality": true, "political_view": true, "race_ethnicity": true,
			"employment_status": true, "coordinate": true,
		},
	})
}

func TestGretelBenchmark(t *testing.T) {
	runBenchmark(t, benchConfig{
		datasetName: "gretelai/synthetic_pii_finance_multilingual",
		dataFile:    "testdata/gretel_pii_samples.json",
		detectableLabels: map[string]bool{
			"email": true, "phone_number": true, "credit_card_number": true,
			"credit_card_security_code": true, "iban": true, "bban": true,
			"ipv4": true, "ipv6": true, "password": true, "account_pin": true,
			"bank_routing_number": true, "swift_bic_code": true,
			"customer_id": true, "employee_id": true, "user_name": true,
			"driver_license_number": true, "passport_number": true, "api_key": true,
		},
		ignoredLabels: map[string]bool{
			"date": true, "date_time": true, "company": true,
			"time": true, "local_latlng": true,
		},
	})
}

func TestPrivyBenchmark(t *testing.T) {
	runBenchmark(t, benchConfig{
		datasetName: "beki/privy (EU financial)",
		dataFile:    "testdata/privy_pii_samples.json",
		detectableLabels: map[string]bool{
			"email_address": true, "phone_number": true, "credit_card": true,
			"iban_code": true, "us_ssn": true, "us_bank_number": true,
			"ip_address": true, "mac_address": true, "password": true,
			"us_passport": true, "us_driver_license": true, "imei": true,
			"url": true, "financial": true,
		},
		ignoredLabels: map[string]bool{},
	})
}

func TestNemotronHealthcareBenchmark(t *testing.T) {
	runBenchmark(t, benchConfig{
		datasetName: "nvidia/Nemotron-PII Healthcare",
		dataFile:    "testdata/nemotron_healthcare_samples.json",
		detectableLabels: map[string]bool{
			"email": true, "ssn": true, "credit_debit_card": true, "phone_number": true,
			"fax_number": true, "ipv4": true, "mac_address": true, "url": true,
			"password": true, "pin": true, "cvv": true, "user_name": true,
			"account_number": true, "bank_routing_number": true, "swift_bic": true,
			"customer_id": true, "employee_id": true, "medical_record_number": true,
			"certificate_license_number": true, "license_plate": true,
			"vehicle_identifier": true, "device_identifier": true,
			"http_cookie": true, "biometric_identifier": true,
			"health_plan_beneficiary_number": true, "postcode": true, "unique_id": true,
		},
		ignoredLabels: map[string]bool{
			"date": true, "date_time": true, "company_name": true,
			"occupation": true, "gender": true, "blood_type": true,
			"religious_belief": true, "country": true, "state": true, "county": true,
			"education_level": true, "time": true, "age": true, "language": true,
			"sexuality": true, "political_view": true, "race_ethnicity": true,
			"employment_status": true,
		},
	})
}

func TestMultiPIIBenchmark(t *testing.T) {
	runBenchmark(t, benchConfig{
		datasetName: "E3-JSI/synthetic-multi-pii-ner-v1 (English)",
		dataFile:    "testdata/multipii_samples.json",
		detectableLabels: map[string]bool{
			"email address": true, "phone number": true, "credit card number": true,
			"credit card last four digits": true, "credit card expiration date": true,
			"ip address": true, "iban": true, "account number": true,
			"national id number": true, "registration number": true,
			"student id number": true, "username": true, "password": true,
			"health insurance number": true, "insurance number": true,
			"person name": true, "person": true, "name": true,
			"address": true, "street address": true, "city": true, "state": true,
			"postal code": true, "credit card type": true,
		},
		ignoredLabels: map[string]bool{
			"date": true, "time": true, "company": true, "company name": true,
			"organization": true, "organization name": true,
			"occupation": true, "job title": true, "position": true, "profession": true,
			"education level": true, "education status": true, "academic activity": true,
			"medical condition": true, "treatment": true, "medication": true, "symptom": true,
			"blood type": true, "dietary restriction": true,
			"percentage": true, "time period": true, "experience duration": true,
			"topic": true, "subject": true, "presentation topic": true,
			"technology": true, "device": true, "data type": true,
			"legal term": true, "legal field": true, "legal profession": true,
			"legal document": true, "legal charge": true, "legal issue": true,
			"financial product": true, "financial amount": true, "financial index": true,
			"finance instrument": true, "investment type": true, "interest rate": true,
			"loan amount": true, "money": true, "interest": true,
			"medical field": true, "medical department": true, "medical procedure": true,
			"medical test": true, "medical history": true, "test result": true,
			"verification type": true, "security vulnerability": true,
			"service": true, "service feature": true, "social media": true,
			"specialization": true, "people group": true,
			"payment method": true, "transaction": true,
			"event name": true, "class name": true, "document": true,
			"identifier type": true, "account type": true,
			"dependent": true, "patient age": true,
			"academic discipline": true, "academic program": true,
			"amount": true, "application type": true,
			"bank": true, "bank branch": true, "bank name": true,
			"banking": true, "banking product": true, "banking term": true,
			"court": true, "degree": true, "destination": true,
			"education institution": true, "educational institution": true,
			"entity type": true, "event": true, "field of study": true,
			"finance term": true, "financial concept": true, "financial feature": true,
			"financial information": true, "financial institution": true, "financial term": true,
			"flight number": true, "government entity": true, "gpa": true,
			"healthcare facility": true, "hobby": true, "hospital": true,
			"institution": true, "insurance plan": true, "insurance provider": true,
			"insurance type": true, "invention": true, "legal institution": true,
			"university": true, "age": true,
		},
	})
}

// --- Pipeline ordering experiments ---

var nemotronConfig = benchConfig{
	datasetName: "nvidia/Nemotron-PII",
	dataFile:    "testdata/nemotron_pii_samples.json",
	detectableLabels: map[string]bool{
		"email": true, "ssn": true, "credit_debit_card": true, "phone_number": true,
		"fax_number": true, "ipv4": true, "mac_address": true, "url": true,
		"password": true, "pin": true, "cvv": true, "user_name": true,
		"account_number": true, "bank_routing_number": true, "swift_bic": true,
		"customer_id": true, "employee_id": true, "medical_record_number": true,
		"certificate_license_number": true, "license_plate": true,
		"vehicle_identifier": true, "device_identifier": true,
		"http_cookie": true, "biometric_identifier": true,
		"health_plan_beneficiary_number": true, "postcode": true,
	},
	ignoredLabels: map[string]bool{
		"date": true, "date_time": true, "company_name": true,
		"occupation": true, "gender": true, "blood_type": true,
		"religious_belief": true, "country": true, "state": true, "county": true,
		"education_level": true, "time": true, "age": true, "language": true,
		"sexuality": true, "political_view": true, "race_ethnicity": true,
		"employment_status": true, "coordinate": true,
	},
}

func withMode(cfg benchConfig, mode string) benchConfig {
	c := cfg
	c.pipelineMode = mode
	return c
}

func TestOPFFirst_Nemotron(t *testing.T)    { runBenchmark(t, withMode(nemotronConfig, "opf_first")) }
func TestGLiNERFirst_Nemotron(t *testing.T) { runBenchmark(t, withMode(nemotronConfig, "gliner_first")) }

func TestOPFFirst_Healthcare(t *testing.T) {
	runBenchmark(t, benchConfig{
		datasetName:  "nvidia/Nemotron-PII Healthcare",
		dataFile:     "testdata/nemotron_healthcare_samples.json",
		pipelineMode: "opf_first",
		detectableLabels: map[string]bool{
			"email": true, "ssn": true, "credit_debit_card": true, "phone_number": true,
			"fax_number": true, "ipv4": true, "mac_address": true, "url": true,
			"password": true, "pin": true, "cvv": true, "user_name": true,
			"account_number": true, "bank_routing_number": true, "swift_bic": true,
			"customer_id": true, "employee_id": true, "medical_record_number": true,
			"certificate_license_number": true, "license_plate": true,
			"vehicle_identifier": true, "device_identifier": true,
			"http_cookie": true, "biometric_identifier": true,
			"health_plan_beneficiary_number": true, "postcode": true, "unique_id": true,
		},
		ignoredLabels: map[string]bool{
			"date": true, "date_time": true, "company_name": true,
			"occupation": true, "gender": true, "blood_type": true,
			"religious_belief": true, "country": true, "county": true,
			"education_level": true, "time": true, "age": true, "language": true,
			"sexuality": true, "political_view": true, "race_ethnicity": true,
			"employment_status": true,
		},
	})
}

func TestGLiNERFirst_Healthcare(t *testing.T) {
	runBenchmark(t, benchConfig{
		datasetName:  "nvidia/Nemotron-PII Healthcare",
		dataFile:     "testdata/nemotron_healthcare_samples.json",
		pipelineMode: "gliner_first",
		detectableLabels: map[string]bool{
			"email": true, "ssn": true, "credit_debit_card": true, "phone_number": true,
			"fax_number": true, "ipv4": true, "mac_address": true, "url": true,
			"password": true, "pin": true, "cvv": true, "user_name": true,
			"account_number": true, "bank_routing_number": true, "swift_bic": true,
			"customer_id": true, "employee_id": true, "medical_record_number": true,
			"certificate_license_number": true, "license_plate": true,
			"vehicle_identifier": true, "device_identifier": true,
			"http_cookie": true, "biometric_identifier": true,
			"health_plan_beneficiary_number": true, "postcode": true, "unique_id": true,
		},
		ignoredLabels: map[string]bool{
			"date": true, "date_time": true, "company_name": true,
			"occupation": true, "gender": true, "blood_type": true,
			"religious_belief": true, "country": true, "county": true,
			"education_level": true, "time": true, "age": true, "language": true,
			"sexuality": true, "political_view": true, "race_ethnicity": true,
			"employment_status": true,
		},
	})
}

func TestOPFFirst_Gretel(t *testing.T) {
	runBenchmark(t, benchConfig{
		datasetName:  "gretelai/synthetic_pii_finance_multilingual",
		dataFile:     "testdata/gretel_pii_samples.json",
		pipelineMode: "opf_first",
		detectableLabels: map[string]bool{
			"email": true, "phone_number": true, "credit_card_number": true,
			"credit_card_security_code": true, "iban": true, "bban": true,
			"ipv4": true, "ipv6": true, "password": true, "account_pin": true,
			"bank_routing_number": true, "swift_bic_code": true,
			"customer_id": true, "employee_id": true, "user_name": true,
			"driver_license_number": true, "passport_number": true, "api_key": true,
		},
		ignoredLabels: map[string]bool{
			"date": true, "date_time": true, "company": true,
			"time": true, "local_latlng": true,
		},
	})
}

func TestGLiNERFirst_Gretel(t *testing.T) {
	runBenchmark(t, benchConfig{
		datasetName:  "gretelai/synthetic_pii_finance_multilingual",
		dataFile:     "testdata/gretel_pii_samples.json",
		pipelineMode: "gliner_first",
		detectableLabels: map[string]bool{
			"email": true, "phone_number": true, "credit_card_number": true,
			"credit_card_security_code": true, "iban": true, "bban": true,
			"ipv4": true, "ipv6": true, "password": true, "account_pin": true,
			"bank_routing_number": true, "swift_bic_code": true,
			"customer_id": true, "employee_id": true, "user_name": true,
			"driver_license_number": true, "passport_number": true, "api_key": true,
		},
		ignoredLabels: map[string]bool{
			"date": true, "date_time": true, "company": true,
			"time": true, "local_latlng": true,
		},
	})
}

func TestOPFFirst_Privy(t *testing.T) {
	runBenchmark(t, benchConfig{
		datasetName:  "beki/privy (EU financial)",
		dataFile:     "testdata/privy_pii_samples.json",
		pipelineMode: "opf_first",
		detectableLabels: map[string]bool{
			"email_address": true, "phone_number": true, "credit_card": true,
			"iban_code": true, "us_ssn": true, "us_bank_number": true,
			"ip_address": true, "mac_address": true, "password": true,
			"us_passport": true, "us_driver_license": true, "imei": true,
			"url": true, "financial": true,
		},
		ignoredLabels: map[string]bool{},
	})
}

func TestGLiNERFirst_Privy(t *testing.T) {
	runBenchmark(t, benchConfig{
		datasetName:  "beki/privy (EU financial)",
		dataFile:     "testdata/privy_pii_samples.json",
		pipelineMode: "gliner_first",
		detectableLabels: map[string]bool{
			"email_address": true, "phone_number": true, "credit_card": true,
			"iban_code": true, "us_ssn": true, "us_bank_number": true,
			"ip_address": true, "mac_address": true, "password": true,
			"us_passport": true, "us_driver_license": true, "imei": true,
			"url": true, "financial": true,
		},
		ignoredLabels: map[string]bool{},
	})
}

func TestOPFFirst_MultiPII(t *testing.T) {
	runBenchmark(t, benchConfig{
		datasetName:  "E3-JSI/synthetic-multi-pii-ner-v1 (English)",
		dataFile:     "testdata/multipii_samples.json",
		pipelineMode: "opf_first",
		detectableLabels: map[string]bool{
			"email address": true, "phone number": true, "credit card number": true,
			"credit card last four digits": true, "credit card expiration date": true,
			"ip address": true, "iban": true, "account number": true,
			"national id number": true, "registration number": true,
			"student id number": true, "username": true, "password": true,
			"health insurance number": true, "insurance number": true,
			"person name": true, "person": true, "name": true,
			"address": true, "street address": true, "city": true, "state": true,
			"postal code": true, "credit card type": true,
		},
		ignoredLabels: map[string]bool{
			"date": true, "time": true, "company": true, "company name": true,
			"organization": true, "organization name": true,
			"occupation": true, "job title": true, "position": true, "profession": true,
			"education level": true, "education status": true, "academic activity": true,
			"medical condition": true, "treatment": true, "medication": true, "symptom": true,
			"blood type": true, "dietary restriction": true,
			"percentage": true, "time period": true, "experience duration": true,
			"topic": true, "subject": true, "presentation topic": true,
			"technology": true, "device": true, "data type": true,
			"legal term": true, "legal field": true, "legal profession": true,
			"legal document": true, "legal charge": true, "legal issue": true,
			"financial product": true, "financial amount": true, "financial index": true,
			"finance instrument": true, "investment type": true, "interest rate": true,
			"loan amount": true, "money": true, "interest": true,
			"medical field": true, "medical department": true, "medical procedure": true,
			"medical test": true, "medical history": true, "test result": true,
			"verification type": true, "security vulnerability": true,
			"service": true, "service feature": true, "social media": true,
			"specialization": true, "people group": true,
			"payment method": true, "transaction": true,
			"event name": true, "class name": true, "document": true,
			"identifier type": true, "account type": true,
			"dependent": true, "patient age": true,
			"academic discipline": true, "academic program": true,
			"amount": true, "application type": true,
			"bank": true, "bank branch": true, "bank name": true,
			"banking": true, "banking product": true, "banking term": true,
			"court": true, "degree": true, "destination": true,
			"education institution": true, "educational institution": true,
			"entity type": true, "event": true, "field of study": true,
			"finance term": true, "financial concept": true, "financial feature": true,
			"financial information": true, "financial institution": true, "financial term": true,
			"flight number": true, "government entity": true, "gpa": true,
			"healthcare facility": true, "hobby": true, "hospital": true,
			"institution": true, "insurance plan": true, "insurance provider": true,
			"insurance type": true, "invention": true, "legal institution": true,
			"university": true, "age": true,
		},
	})
}

func TestGLiNERFirst_MultiPII(t *testing.T) {
	runBenchmark(t, benchConfig{
		datasetName:  "E3-JSI/synthetic-multi-pii-ner-v1 (English)",
		dataFile:     "testdata/multipii_samples.json",
		pipelineMode: "gliner_first",
		detectableLabels: map[string]bool{
			"email address": true, "phone number": true, "credit card number": true,
			"credit card last four digits": true, "credit card expiration date": true,
			"ip address": true, "iban": true, "account number": true,
			"national id number": true, "registration number": true,
			"student id number": true, "username": true, "password": true,
			"health insurance number": true, "insurance number": true,
			"person name": true, "person": true, "name": true,
			"address": true, "street address": true, "city": true, "state": true,
			"postal code": true, "credit card type": true,
		},
		ignoredLabels: map[string]bool{
			"date": true, "time": true, "company": true, "company name": true,
			"organization": true, "organization name": true,
			"occupation": true, "job title": true, "position": true, "profession": true,
			"education level": true, "education status": true, "academic activity": true,
			"medical condition": true, "treatment": true, "medication": true, "symptom": true,
			"blood type": true, "dietary restriction": true,
			"percentage": true, "time period": true, "experience duration": true,
			"topic": true, "subject": true, "presentation topic": true,
			"technology": true, "device": true, "data type": true,
			"legal term": true, "legal field": true, "legal profession": true,
			"legal document": true, "legal charge": true, "legal issue": true,
			"financial product": true, "financial amount": true, "financial index": true,
			"finance instrument": true, "investment type": true, "interest rate": true,
			"loan amount": true, "money": true, "interest": true,
			"medical field": true, "medical department": true, "medical procedure": true,
			"medical test": true, "medical history": true, "test result": true,
			"verification type": true, "security vulnerability": true,
			"service": true, "service feature": true, "social media": true,
			"specialization": true, "people group": true,
			"payment method": true, "transaction": true,
			"event name": true, "class name": true, "document": true,
			"identifier type": true, "account type": true,
			"dependent": true, "patient age": true,
			"academic discipline": true, "academic program": true,
			"amount": true, "application type": true,
			"bank": true, "bank branch": true, "bank name": true,
			"banking": true, "banking product": true, "banking term": true,
			"court": true, "degree": true, "destination": true,
			"education institution": true, "educational institution": true,
			"entity type": true, "event": true, "field of study": true,
			"finance term": true, "financial concept": true, "financial feature": true,
			"financial information": true, "financial institution": true, "financial term": true,
			"flight number": true, "government entity": true, "gpa": true,
			"healthcare facility": true, "hobby": true, "hospital": true,
			"institution": true, "insurance plan": true, "insurance provider": true,
			"insurance type": true, "invention": true, "legal institution": true,
			"university": true, "age": true,
		},
	})
}

func runBenchmark(t *testing.T, cfg benchConfig) {
	samples := loadBenchSamples(t, cfg.dataFile)

	fakeAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		w.Write([]byte(`{"id":"msg_bench","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer fakeAPI.Close()

	dir := t.TempDir()
	ca, err := certgen.GenerateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	fakeHostPort := fakeAPI.Listener.Addr().String()
	host, _, _ := net.SplitHostPort(fakeHostPort)
	df := domain.New([]string{host}, nil)

	presidioLayer := presidio.New()
	entropyLayer := entropy.New(3.5, 16)
	gateLayer := contextgate.New()

	var pip *scanner.Pipeline
	var cleanups []func()

	mode := cfg.pipelineMode
	if mode == "" {
		mode = "default"
	}

	switch mode {
	case "opf_first":
		opfLayer, opfCleanup := setupOPF(t)
		cleanups = append(cleanups, opfCleanup)
		glinerLayer, glinerCleanup := setupGLiNER(t)
		cleanups = append(cleanups, glinerCleanup)
		pip = scanner.NewPipeline(opfLayer, presidioLayer, entropyLayer, glinerLayer, gateLayer)
		t.Log("Pipeline: OPF → presidio → entropy → GLiNER → contextgate")

	case "gliner_first":
		glinerLayer, glinerCleanup := setupGLiNER(t)
		cleanups = append(cleanups, glinerCleanup)
		pip = scanner.NewPipeline(glinerLayer, presidioLayer, entropyLayer, gateLayer)
		t.Log("Pipeline: GLiNER → presidio → entropy → contextgate")

	default:
		glinerLayer, glinerCleanup := setupGLiNER(t)
		cleanups = append(cleanups, glinerCleanup)
		pip = scanner.NewPipeline(presidioLayer, entropyLayer, glinerLayer, gateLayer)
		t.Log("Pipeline: presidio → entropy → GLiNER → contextgate (default)")
	}
	defer func() {
		for _, fn := range cleanups {
			fn()
		}
	}()

	pipeline := pip
	cache := scanner.NewCache(10000)
	fb := fileblock.New([]string{".env"}, true)
	coord := coordinator.New(pipeline, cache, fb)

	var reports []*store.ScanReport
	onScan := func(r *store.ScanReport) { reports = append(reports, r) }

	p, err := proxy.NewProxy(ca, df, coord, nil, onScan)
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}
	proxyAddr, err := p.Start(0)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()

	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   10 * time.Second,
	}

	type catchDetail struct {
		PIILabel string
		PIIValue string
		ByLayer  string
		ByLabel  string
	}

	var allCaught []catchDetail
	var allMissed []catchDetail
	var allFP []catchDetail
	var totalLatency int64

	layerCaught := make(map[string]int)
	layerFP := make(map[string]int)

	for i, s := range samples {
		reqBody := map[string]interface{}{
			"model": "claude-sonnet-4-20250514",
			"messages": []map[string]interface{}{
				{"role": "user", "content": s.Text},
			},
		}
		bodyBytes, _ := json.Marshal(reqBody)

		start := time.Now()
		resp, err := client.Post(fakeAPI.URL+"/v1/messages", "application/json", bytes.NewReader(bodyBytes))
		latency := time.Since(start).Milliseconds()

		if err != nil {
			t.Logf("sample %d (%s): request error: %v", i, s.ID, err)
			continue
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()

		time.Sleep(5 * time.Millisecond)

		reportIdx := -1
		if len(reports) > i {
			reportIdx = i
		} else if len(reports) > 0 {
			reportIdx = len(reports) - 1
		}

		for _, pii := range s.PII {
			if cfg.ignoredLabels[pii.Label] {
				continue
			}
			pv := pii.ValueString()
			wasCaught := false
			caughtLayer := ""
			caughtLabel := ""
			if reportIdx >= 0 && reportIdx < len(reports) {
				for _, red := range reports[reportIdx].Redactions {
					if strings.Contains(pv, red.Original) || strings.Contains(red.Original, pv) ||
						(red.Start <= pii.End && red.End >= pii.Start) {
						wasCaught = true
						caughtLayer = red.Layer
						caughtLabel = red.Label
						break
					}
				}
			}

			if wasCaught {
				allCaught = append(allCaught, catchDetail{pii.Label, pv, caughtLayer, caughtLabel})
				layerCaught[caughtLayer]++
			} else {
				allMissed = append(allMissed, catchDetail{pii.Label, pv, "", ""})
			}
		}

		if reportIdx >= 0 && reportIdx < len(reports) {
			for _, red := range reports[reportIdx].Redactions {
				matchesKnown := false
				for _, pii := range s.PII {
					pv := pii.ValueString()
					if strings.Contains(pv, red.Original) || strings.Contains(red.Original, pv) ||
						(red.Start <= pii.End && red.End >= pii.Start) {
						matchesKnown = true
						break
					}
				}
				if !matchesKnown {
					allFP = append(allFP, catchDetail{"", red.Original, red.Layer, red.Label})
					layerFP[red.Layer]++
				}
			}
		}

		totalLatency += latency
	}

	totalPII := len(allCaught) + len(allMissed)
	totalCaught := len(allCaught)
	totalMissed := len(allMissed)
	totalFP := len(allFP)

	precision := float64(0)
	if totalCaught+totalFP > 0 {
		precision = float64(totalCaught) / float64(totalCaught+totalFP) * 100
	}
	recall := float64(0)
	if totalPII > 0 {
		recall = float64(totalCaught) / float64(totalPII) * 100
	}
	f1 := float64(0)
	if precision+recall > 0 {
		f1 = 2 * (precision * recall) / (precision + recall)
	}
	avgLatency := float64(totalLatency) / float64(len(samples))

	labelCount := 0
	allPIILabels := make(map[string]bool)
	for _, s := range samples {
		for _, p := range s.PII {
			allPIILabels[p.Label] = true
		}
	}
	labelCount = len(allPIILabels)

	fmt.Println("\n" + strings.Repeat("=", 90))
	fmt.Println("REDACTR END-TO-END PROXY BENCHMARK RESULTS")
	fmt.Printf("Dataset: %s (%d samples, %d PII entities, %d label types)\n", cfg.datasetName, len(samples), totalPII, labelCount)
	fmt.Println(strings.Repeat("=", 90))

	fmt.Printf("\n%-30s %d\n", "Total Samples:", len(samples))
	fmt.Printf("%-30s %d\n", "Total PII Entities:", totalPII)
	fmt.Printf("%-30s %d\n", "Correctly Caught:", totalCaught)
	fmt.Printf("%-30s %d\n", "Missed:", totalMissed)
	fmt.Printf("%-30s %d\n", "False Positives:", totalFP)
	fmt.Printf("\n%-30s %.1f%%\n", "Precision:", precision)
	fmt.Printf("%-30s %.1f%%\n", "Recall:", recall)
	fmt.Printf("%-30s %.1f\n", "F1 Score:", f1)
	fmt.Printf("\n%-30s %.2fms\n", "Avg Latency/Request:", avgLatency)
	fmt.Printf("%-30s %dms\n", "Total Time:", totalLatency)

	// --- PER-LAYER BREAKDOWN ---
	fmt.Println("\n" + strings.Repeat("=", 90))
	fmt.Println("PER-LAYER DETECTION BREAKDOWN")
	fmt.Println(strings.Repeat("=", 90))
	fmt.Printf("%-20s %10s %10s %10s\n", "Layer", "Caught", "False Pos", "Precision")
	fmt.Println(strings.Repeat("-", 52))

	allLayerNames := make(map[string]bool)
	for k := range layerCaught {
		allLayerNames[k] = true
	}
	for k := range layerFP {
		allLayerNames[k] = true
	}
	for layer := range allLayerNames {
		c := layerCaught[layer]
		fp := layerFP[layer]
		lp := float64(0)
		if c+fp > 0 {
			lp = float64(c) / float64(c+fp) * 100
		}
		fmt.Printf("%-20s %10d %10d %9.1f%%\n", layer, c, fp, lp)
	}

	// --- WHAT EACH LAYER CAUGHT ---
	fmt.Println("\n" + strings.Repeat("=", 90))
	fmt.Println("WHAT EACH LAYER CAUGHT (by PII category)")
	fmt.Println(strings.Repeat("=", 90))

	layerLabelCaught := make(map[string]map[string]int)
	for _, c := range allCaught {
		if layerLabelCaught[c.ByLayer] == nil {
			layerLabelCaught[c.ByLayer] = make(map[string]int)
		}
		layerLabelCaught[c.ByLayer][c.PIILabel]++
	}

	for layer, labels := range layerLabelCaught {
		fmt.Printf("\n  [%s]\n", layer)
		type kv struct {
			k string
			v int
		}
		var sorted []kv
		for k, v := range labels {
			sorted = append(sorted, kv{k, v})
		}
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].v > sorted[j].v })
		for _, s := range sorted {
			fmt.Printf("    %-25s %d\n", s.k, s.v)
		}
	}

	// --- PER-LABEL BREAKDOWN ---
	fmt.Println("\n" + strings.Repeat("=", 90))
	fmt.Println("PER-LABEL BREAKDOWN")
	fmt.Println(strings.Repeat("=", 90))
	fmt.Printf("%-30s %8s %8s %8s %8s\n", "Label", "Total", "Caught", "Missed", "Rate")
	fmt.Println(strings.Repeat("-", 66))

	caughtByLabel := make(map[string]int)
	missedByLabel := make(map[string]int)
	for _, c := range allCaught {
		caughtByLabel[c.PIILabel]++
	}
	for _, m := range allMissed {
		missedByLabel[m.PIILabel]++
	}

	type labelStat struct {
		label                 string
		total, caught, missed int
		rate                  float64
		detectable            bool
	}
	var labelStats []labelStat
	for label := range allPIILabels {
		c := caughtByLabel[label]
		m := missedByLabel[label]
		total := c + m
		rate := float64(0)
		if total > 0 {
			rate = float64(c) / float64(total) * 100
		}
		labelStats = append(labelStats, labelStat{label, total, c, m, rate, cfg.detectableLabels[label]})
	}
	sort.Slice(labelStats, func(i, j int) bool { return labelStats[i].rate > labelStats[j].rate })

	for _, ls := range labelStats {
		marker := ""
		if !ls.detectable {
			marker = " *"
		}
		fmt.Printf("%-30s %8d %8d %8d %7.1f%%%s\n", ls.label, ls.total, ls.caught, ls.missed, ls.rate, marker)
	}
	fmt.Println("\n* = PII type not in regex/entropy target set (names, addresses, dates)")

	// --- FALSE POSITIVES ---
	if totalFP > 0 {
		fmt.Println("\n" + strings.Repeat("=", 90))
		fmt.Println("FALSE POSITIVES")
		fmt.Println(strings.Repeat("=", 90))
		fpByLabel := make(map[string]int)
		for _, fp := range allFP {
			fpByLabel[fp.ByLabel]++
		}
		for label, count := range fpByLabel {
			fmt.Printf("  %-20s %d (layer: ", label, count)
			for _, fp := range allFP {
				if fp.ByLabel == label {
					fmt.Printf("%s ", fp.ByLayer)
					break
				}
			}
			fmt.Println(")")
		}
		fmt.Println("\n  Sample false positive values:")
		shown := 0
		for _, fp := range allFP {
			if shown >= 15 {
				fmt.Printf("  ... and %d more\n", totalFP-15)
				break
			}
			val := fp.PIIValue
			if len(val) > 40 {
				val = val[:40] + "..."
			}
			fmt.Printf("  [%s/%s] %q\n", fp.ByLayer, fp.ByLabel, val)
			shown++
		}
	}

	// --- DETECTABLE VS NOT ---
	detectablePII := 0
	detectableCaught := 0
	for _, c := range allCaught {
		if cfg.detectableLabels[c.PIILabel] {
			detectableCaught++
		}
	}
	for _, m := range allMissed {
		if cfg.detectableLabels[m.PIILabel] {
			detectablePII++
		}
	}
	detectablePII += detectableCaught

	detectableRecall := float64(0)
	if detectablePII > 0 {
		detectableRecall = float64(detectableCaught) / float64(detectablePII) * 100
	}
	fmt.Println("\n" + strings.Repeat("=", 90))
	fmt.Println("DETECTION BY SCANNER CAPABILITY")
	fmt.Println(strings.Repeat("=", 90))
	fmt.Printf("%-35s %d/%d (%.1f%%)\n", "Regex+Entropy detectable PII:", detectableCaught, detectablePII, detectableRecall)
	fmt.Printf("%-35s %d\n", "ML-only PII (names, addresses):", totalPII-detectablePII)
	fmt.Printf("%-35s %d\n", "Total PII in dataset:", totalPII)

	fmt.Println("\n" + strings.Repeat("=", 90))

	// --- JSON SUMMARY ---
	summary := map[string]interface{}{
		"dataset":           cfg.datasetName,
		"samples":           len(samples),
		"total_pii":         totalPII,
		"caught":            totalCaught,
		"missed":            totalMissed,
		"false_positives":   totalFP,
		"precision_pct":     precision,
		"recall_pct":        recall,
		"f1_score":          f1,
		"avg_latency_ms":    avgLatency,
		"total_time_ms":     totalLatency,
		"detectable_pii":    detectablePII,
		"detectable_caught": detectableCaught,
		"per_layer_caught":  layerCaught,
		"per_layer_fp":      layerFP,
		"caught_by_label":   caughtByLabel,
		"missed_by_label":   missedByLabel,
	}
	summaryJSON, _ := json.MarshalIndent(summary, "", "  ")
	fmt.Println("\n--- RESULTS JSON ---")
	fmt.Println(string(summaryJSON))
}
