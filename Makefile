GOLANGCI_LINT_VERSION := v2.8.0
TOOLS_DIR := ./bin
GOLANGCI_LINT := $(TOOLS_DIR)/golangci-lint
GO_IMAGE := golang:1.24
GOLANGCI_LINT_IMAGE := golangci/golangci-lint:$(GOLANGCI_LINT_VERSION)
ROOT_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
WORKDIR := /src
DOCKER_RUN := docker run --rm -v "$(ROOT_DIR):$(WORKDIR)" -w $(WORKDIR) --user $$(id -u):$$(id -g) -e HOME=$(WORKDIR) -e XDG_CACHE_HOME=$(WORKDIR)/.cache
MODULE_DIR := tools/scrapligo-backup
LINT_WORKDIR := $(WORKDIR)/$(MODULE_DIR)
LINT_DOCKER_RUN := docker run --rm -v "$(ROOT_DIR):$(WORKDIR)" -w $(LINT_WORKDIR) --user $$(id -u):$$(id -g) -e HOME=$(WORKDIR) -e XDG_CACHE_HOME=$(WORKDIR)/.cache

.PHONY: build tools lint lint-fix clean-tools

build:
	mkdir -p bin
	go build -o bin/nck-scrapli ./tools/scrapligo-backup

tools:
	mkdir -p $(TOOLS_DIR)
	docker pull $(GO_IMAGE)
	docker pull $(GOLANGCI_LINT_IMAGE)

lint: tools
	@test -f "$(ROOT_DIR)/.golangci.yml" || (echo ".golangci.yml is required for lint"; exit 1)
	mkdir -p "$(ROOT_DIR)/.cache"
	$(LINT_DOCKER_RUN) $(GOLANGCI_LINT_IMAGE) golangci-lint run -c $(WORKDIR)/.golangci.yml ./...

lint-fix: tools
	@test -f "$(ROOT_DIR)/.golangci.yml" || (echo ".golangci.yml is required for lint"; exit 1)
	mkdir -p "$(ROOT_DIR)/.cache"
	$(LINT_DOCKER_RUN) $(GOLANGCI_LINT_IMAGE) golangci-lint run --fix -c $(WORKDIR)/.golangci.yml ./...

clean-tools:
	rm -rf $(TOOLS_DIR)
