CLUSTER   ?= kscan-playground
KCTX      := kind-$(CLUSTER)
IMAGE     ?= kscan:dev
BIN       := bin/kscan

.PHONY: help build test lint scan-files run docker-build \
        playground-up playground-deploy playground-scan playground-ui playground-logs playground-down

help: ## Show targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the kscan binary into bin/
	go build -o $(BIN) ./cmd/kscan

test: ## Run unit + policy tests
	go test ./...

lint: ## go vet
	go vet ./...

scan-files: build ## Scan the playground manifests offline (no cluster needed)
	$(BIN) scan --files playground,deploy

run: build ## Run the service locally against your current kubeconfig context (UI on :8080)
	$(BIN) serve --interval 1m --policies deploy/custom-policies

docker-build: ## Build the container image
	docker build -t $(IMAGE) .

# --- playground ------------------------------------------------------------

playground-up: ## Create a kind cluster, deploy vulnerable + secure workloads and kscan
	@kind get clusters 2>/dev/null | grep -qx $(CLUSTER) || kind create cluster --config playground/kind-config.yaml
	kubectl --context $(KCTX) apply -f playground/vulnerable -f playground/secure
	$(MAKE) playground-deploy
	@echo
	@echo "Playground ready. Next:"
	@echo "  make playground-ui     # dashboard + policy playground on http://localhost:8080"
	@echo "  make playground-scan   # one-shot CLI scan of the cluster"

playground-deploy: docker-build ## (Re)build the image, load it into kind and deploy kscan
	kind load docker-image $(IMAGE) --name $(CLUSTER)
	kubectl --context $(KCTX) apply -k deploy
	kubectl --context $(KCTX) -n kscan rollout restart deployment/kscan
	kubectl --context $(KCTX) -n kscan rollout status deployment/kscan --timeout=120s

playground-scan: build ## One-shot scan of the playground cluster from your machine
	$(BIN) scan --context $(KCTX) --policies deploy/custom-policies

playground-ui: ## Port-forward the in-cluster kscan UI to http://localhost:8080
	kubectl --context $(KCTX) -n kscan port-forward svc/kscan 8080:8080

playground-logs: ## Tail the in-cluster scanner logs
	kubectl --context $(KCTX) -n kscan logs -f deploy/kscan

playground-down: ## Delete the kind cluster
	kind delete cluster --name $(CLUSTER)
