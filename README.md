# CEL_K8sScanner
A Kubernetes security scanner written in Go. It reads your cluster through the Kubernetes API (read-only, no access to Secrets), checks it with CEL policies mapped to MITRE ATT&amp;CK and the Kubernetes Threat Matrix, and shows every finding with the the fixed YAML to apply it (based on business needs)
