NPM_CMD?=npm

GO_CMD?=go

GOLANGCI_LINT_CMD?=$(GO_CMD) tool golangci-lint

GOVULNCHECK_CMD?=$(GO_CMD) tool govulncheck

.DEFAULT_GOAL := .default

.default: format build lint test

.PHONY: help
help: ## Show help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: npm-build ## Build bin/auth
	$(GO_CMD) build -o bin/ ./cmd/...

.PHONY: format
format: ## Format the code and tidy go.mod
	$(GO_CMD) fix ./...
	$(GOLANGCI_LINT_CMD) fmt ./...
	$(GO_CMD) mod tidy

.PHONY: lint
lint: ## Run the linters
	$(GOLANGCI_LINT_CMD) run ./...
	$(GOVULNCHECK_CMD) ./...

.PHONY: test
test: ## Run the tests
	$(GO_CMD) test ./...

.which-npm:
	@which $(NPM_CMD) > /dev/null || (echo "Install Node.js from https://nodejs.org/en/download" && exit 1)

.PHONY: dep
dep: .which-npm ## Install the stylesheet build tools
	$(NPM_CMD) install

# The built stylesheets are committed and embedded, so go build alone needs no Node.
.PHONY: npm-build
npm-build: .which-npm ## Build the stylesheets
	$(NPM_CMD) run build:css
