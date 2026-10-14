// Package taxonomy is the catalog of threat techniques policies may map to:
//
//   - MITRE ATT&CK v20, Containers matrix (https://attack.mitre.org/matrices/enterprise/containers/)
//   - Redguard Kubernetes Threat Matrix (https://kubernetes-threat-matrix.redguard.ch/)
//
// Policies reference techniques by their real identifiers and are rejected at
// load time if they reference anything not in this catalog. The Redguard
// matrix has no technique IDs, so its techniques are identified by their page
// path ("<tactic>/<technique>").
package taxonomy

import (
	"fmt"
	"strings"
)

// Tactics of the ATT&CK Containers matrix, in matrix order.
var Tactics = []Tactic{
	{"TA0001", "Initial Access"},
	{"TA0002", "Execution"},
	{"TA0003", "Persistence"},
	{"TA0004", "Privilege Escalation"},
	{"TA0005", "Stealth"},
	{"TA0112", "Defense Impairment"},
	{"TA0006", "Credential Access"},
	{"TA0007", "Discovery"},
	{"TA0008", "Lateral Movement"},
	{"TA0040", "Impact"},
}

type Tactic struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Technique is an ATT&CK technique or sub-technique as referenced in findings.
type Technique struct {
	ID     string `json:"id"`
	Name   string `json:"name"` // "Parent: Sub-technique" for sub-techniques
	URL    string `json:"url"`
	tactic []string
}

// MatrixTechnique is a Redguard Kubernetes Threat Matrix technique.
type MatrixTechnique struct {
	Path   string `json:"path"` // e.g. "privilege-escalation/privileged-container"
	Tactic string `json:"tactic"`
	Name   string `json:"name"`
	URL    string `json:"url"`
}

const (
	ia  = "Initial Access"
	ex  = "Execution"
	pe  = "Persistence"
	pr  = "Privilege Escalation"
	st  = "Stealth"
	di  = "Defense Impairment"
	ca  = "Credential Access"
	dis = "Discovery"
	lm  = "Lateral Movement"
	im  = "Impact"
)

// ATT&CK v20 Containers matrix: technique ID -> name and the tactics it
// appears under in that matrix.
var mitre = map[string]struct {
	name    string
	tactics []string
}{
	"T1190":     {"Exploit Public-Facing Application", []string{ia}},
	"T1133":     {"External Remote Services", []string{ia, pe}},
	"T1078":     {"Valid Accounts", []string{ia, pe, pr, st}},
	"T1078.001": {"Default Accounts", []string{ia, pe, pr, st}},
	"T1078.003": {"Local Accounts", []string{ia, pe, pr, st}},
	"T1059":     {"Command and Scripting Interpreter", []string{ex}},
	"T1059.013": {"Container CLI/API", []string{ex}},
	"T1609":     {"Container Administration Command", []string{ex}},
	"T1610":     {"Deploy Container", []string{ex}},
	"T1053":     {"Scheduled Task/Job", []string{ex, pe, pr}},
	"T1053.007": {"Container Orchestration Job", []string{ex, pe, pr}},
	"T1204":     {"User Execution", []string{ex}},
	"T1204.003": {"Malicious Image", []string{ex}},
	"T1098":     {"Account Manipulation", []string{pe, pr}},
	"T1098.006": {"Additional Container Cluster Roles", []string{pe, pr}},
	"T1136":     {"Create Account", []string{pe}},
	"T1136.001": {"Local Account", []string{pe}},
	"T1543":     {"Create or Modify System Process", []string{pe, pr}},
	"T1543.005": {"Container Service", []string{pe, pr}},
	"T1525":     {"Implant Internal Image", []string{pe}},
	"T1611":     {"Escape to Host", []string{pr}},
	"T1068":     {"Exploitation for Privilege Escalation", []string{pr}},
	"T1612":     {"Build Image on Host", []string{st}},
	"T1070":     {"Indicator Removal", []string{st}},
	"T1036":     {"Masquerading", []string{st}},
	"T1036.005": {"Match Legitimate Resource Name or Location", []string{st}},
	"T1036.010": {"Masquerade Account Name", []string{st}},
	"T1685":     {"Disable or Modify Tools", []string{di}},
	"T1110":     {"Brute Force", []string{ca}},
	"T1110.001": {"Password Guessing", []string{ca}},
	"T1110.003": {"Password Spraying", []string{ca}},
	"T1110.004": {"Credential Stuffing", []string{ca}},
	"T1528":     {"Steal Application Access Token", []string{ca}},
	"T1552":     {"Unsecured Credentials", []string{ca}},
	"T1552.001": {"Credentials In Files", []string{ca}},
	"T1552.007": {"Container API", []string{ca}},
	"T1613":     {"Container and Resource Discovery", []string{dis}},
	"T1046":     {"Network Service Discovery", []string{dis}},
	"T1069":     {"Permission Groups Discovery", []string{dis}},
	"T1550":     {"Use Alternate Authentication Material", []string{lm}},
	"T1550.001": {"Application Access Token", []string{lm}},
	"T1485":     {"Data Destruction", []string{im}},
	"T1499":     {"Endpoint Denial of Service", []string{im}},
	"T1490":     {"Inhibit System Recovery", []string{im}},
	"T1498":     {"Network Denial of Service", []string{im}},
	"T1496":     {"Resource Hijacking", []string{im}},
	"T1496.001": {"Compute Hijacking", []string{im}},
	"T1496.002": {"Bandwidth Hijacking", []string{im}},
}

const redguardBase = "https://kubernetes-threat-matrix.redguard.ch/"

var redguardTactics = map[string]string{
	"initial-access":       "Initial access",
	"execution":            "Execution",
	"persistence":          "Persistence",
	"privilege-escalation": "Privilege escalation",
	"defense-evasion":      "Defense evasion",
	"credential-access":    "Credential access",
	"discovery":            "Discovery",
	"lateral-movement":     "Lateral movement",
	"collection":           "Collection",
	"impact":               "Impact",
}

// Redguard technique page paths -> names, copied verbatim from the matrix.
var redguard = map[string]string{
	"initial-access/using-cloud":                                        "Using Cloud",
	"initial-access/compromised-images-in-registry":                     "Compromised images in registry",
	"initial-access/kubeconfig-file":                                    "Kubeconfig file",
	"initial-access/application-vulnerability":                          "Application vulnerability",
	"initial-access/exposed-sensitive-interfaces":                       "Exposed sensitive interfaces",
	"execution/exec-into-container":                                     "Exec into Container",
	"execution/bash-cmd-in-container":                                   "bash/cmd in container",
	"execution/new-container":                                           "New container",
	"execution/application-exploit-rce":                                 "Application exploit (RCE)",
	"execution/ssh-server-running-in-inside-container":                  "SSH server running in inside container",
	"execution/sidecar-injection":                                       "Sidecar injection",
	"persistence/backdoor-container":                                    "Backdoor Container",
	"persistence/writable-hostpath-mount":                               "Writable hostPath mount",
	"persistence/kubernetes-cronjob":                                    "Kubernetes CronJob",
	"persistence/malicious-admission-controller":                        "Malicious admission controller",
	"privilege-escalation/privileged-container":                         "Privileged Container",
	"privilege-escalation/cluster-admin-binding":                        "Cluster-admin binding",
	"privilege-escalation/hostpath-mount":                               "hostPath mount",
	"privilege-escalation/access-cloud-resources":                       "Access cloud resources",
	"privilege-escalation/disable-namespacing":                          "Disable Namespacing",
	"defense-evasion/clear-container-logs":                              "Clear Container Logs",
	"defense-evasion/delete-k8s-events":                                 "Delete k8s events",
	"defense-evasion/pod-container-name-similarity":                     "Pod / container name similarity",
	"defense-evasion/connect-from-proxy-server":                         "Connect from proxy server",
	"credential-access/list-k8s-secrets":                                "List K8s secrets",
	"credential-access/mount-service-principal":                         "Mount service principal",
	"credential-access/access-container-service-account":                "Access container service account",
	"credential-access/applications-credentials-in-configuration-files": "Applications credentials in configuration files",
	"credential-access/access-managed-identity-credentials":             "Access managed identity credentials",
	"credential-access/malicious-admission-controller":                  "Malicious admission controller",
	"discovery/access-the-k8s-api-server":                               "Access the K8s API server",
	"discovery/access-kubelet-api":                                      "Access Kubelet API",
	"discovery/network-mapping":                                         "Network mapping",
	"discovery/access-kubernetes-dashboard":                             "Access Kubernetes dashboard",
	"discovery/instance-metadata-api":                                   "Instance metadata API",
	"lateral-movement/access-cloud-resources":                           "Access cloud resources",
	"lateral-movement/container-service-account":                        "Container service account",
	"lateral-movement/cluster-internal-networking":                      "Cluster internal networking",
	"lateral-movement/applications-credentials-in-configuration-files":  "Applications credentials in configuration files",
	"lateral-movement/writable-volume-mounts-on-the-host":               "Writable volume mounts on the host",
	"lateral-movement/coredns-poisoning":                                "CoreDNS poisoning",
	"lateral-movement/arp-poisoning-and-ip-spoofing":                    "ARP poisoning and IP spoofing",
	"collection/images-from-a-private-repository":                       "Images from a private repository",
	"impact/data-destruction":                                           "Data Destruction",
	"impact/ressource-hijacking":                                        "Ressource hijacking",
	"impact/denial-of-service":                                          "Denial of Service",
}

// LookupTechnique resolves an ATT&CK technique ID from the Containers matrix.
func LookupTechnique(id string) (Technique, error) {
	t, ok := mitre[id]
	if !ok {
		return Technique{}, fmt.Errorf("%q is not a technique in the ATT&CK Containers matrix", id)
	}
	name := t.name
	parent, sub, isSub := strings.Cut(id, ".")
	if isSub {
		name = mitre[parent].name + ": " + t.name
	}
	url := "https://attack.mitre.org/techniques/" + parent + "/"
	if isSub {
		url += sub + "/"
	}
	return Technique{ID: id, Name: name, URL: url, tactic: t.tactics}, nil
}

// HasTactic reports whether the technique appears under tactic in the matrix.
func (t Technique) HasTactic(tactic string) bool {
	for _, tt := range t.tactic {
		if tt == tactic {
			return true
		}
	}
	return false
}

// Tactics returns the tactics the technique appears under.
func (t Technique) Tactics() []string { return t.tactic }

// LookupMatrix resolves a Redguard Kubernetes Threat Matrix technique path.
func LookupMatrix(path string) (MatrixTechnique, error) {
	path = strings.Trim(path, "/")
	name, ok := redguard[path]
	if !ok {
		return MatrixTechnique{}, fmt.Errorf("%q is not a technique in the Redguard Kubernetes Threat Matrix (use <tactic>/<technique> as in its URLs)", path)
	}
	tactic, _, _ := strings.Cut(path, "/")
	return MatrixTechnique{Path: path, Tactic: redguardTactics[tactic], Name: name, URL: redguardBase + path + "/"}, nil
}

// IsTactic reports whether name is a tactic of the Containers matrix.
func IsTactic(name string) bool {
	for _, t := range Tactics {
		if t.Name == name {
			return true
		}
	}
	return false
}
