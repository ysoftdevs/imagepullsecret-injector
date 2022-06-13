# Image URL to use all building/pushing image targets;
# Use your own docker registry and image name for dev/test by overridding the
# IMAGE_REPO, IMAGE_NAME and IMAGE_TAG environment variable.
REPOSITORY_BASE ?= ghcr.io
IMAGE_REPO ?= $(REPOSITORY_BASE)/ysoftdevs/imagepullsecret-injector
IMAGE_NAME ?= imagepullsecret-injector
GENERATOR_IMAGE_NAME ?= webhook-cert-generator

# Github host to use for checking the source tree;
GIT_HOST ?= github.com/ysoftdevs

PWD := $(shell pwd)
BASE_DIR := $(shell basename $(PWD))
REPO_ROOT := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

# Keep an existing GOPATH, make a private one if it is undefined
GOPATH_DEFAULT := $(PWD)/.go
export GOPATH ?= $(GOPATH_DEFAULT)
TESTARGS_DEFAULT := "-v"
export TESTARGS ?= $(TESTARGS_DEFAULT)
DEST := $(GOPATH)/src/$(GIT_HOST)/$(BASE_DIR)
IMAGE_TAG ?= $(shell cat "$(REPO_ROOT)/VERSION")


LOCAL_OS := $(shell uname)
ifeq ($(LOCAL_OS),Linux)
    TARGET_OS ?= linux
    XARGS_FLAGS="-r"
else ifeq ($(LOCAL_OS),Darwin)
    TARGET_OS ?= darwin
    XARGS_FLAGS=
else
    $(error "This system's OS $(LOCAL_OS) isn't recognized/supported")
endif

all: fmt lint test build docker-image

ifeq (,$(wildcard go.mod))
ifneq ("$(realpath $(DEST))", "$(realpath $(PWD))")
    $(error Please run 'make' from $(DEST). Current directory is $(PWD))
endif
endif

############################################################
# format section
############################################################

fmt:
	@go fmt ./cmd/...

############################################################
# lint section
############################################################

lint:
	@echo "Runing the golangci-lint..."

############################################################
# test section
############################################################

test:
	@echo "Running the tests for $(IMAGE_NAME)..."
	@go test $(TESTARGS) ./...

############################################################
# build section
############################################################

vendor:
	@echo "Vendoring..."
	@go mod vendor

build:
	@echo "Building the $(IMAGE_NAME) binary..."
	@CGO_ENABLED=0 go build -o build/_output/bin/$(IMAGE_NAME) ./cmd/

build-linux:
	@echo "Building the $(IMAGE_NAME) binary for Docker (linux)..."
	@GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o build/_output/linux/bin/$(IMAGE_NAME) ./cmd/

############################################################
# Containerd image section
############################################################

containerd-image: containerd-login containerd-image containerd-image

containerd-login:
	@echo "$(DOCKER_TOKEN)" | nerdctl login -u "$(DOCKER_USER)" --password-stdin "$(REPOSITORY_BASE)"

containerd-logout:
	@docker logout

containerd-build:
	@echo "Building the docker image: $(IMAGE_REPO)/$(IMAGE_NAME):$(IMAGE_TAG)..."
	@nerdctl build -t $(IMAGE_REPO)/$(IMAGE_NAME):$(IMAGE_TAG) -f build/Dockerfile .
	@echo "Building the docker image: $(IMAGE_REPO)/$(GENERATOR_IMAGE_NAME):$(IMAGE_TAG)..."
	@nerdctl build -t $(IMAGE_REPO)/$(GENERATOR_IMAGE_NAME):$(IMAGE_TAG) -f build/Dockerfile.cert-generator .

containerd-push: containerd-build-image
	@echo "Pushing the docker image for $(IMAGE_REPO)/$(IMAGE_NAME):$(IMAGE_TAG) and $(IMAGE_REPO)/$(IMAGE_NAME):latest..."
	@nerdctl tag $(IMAGE_REPO)/$(IMAGE_NAME):$(IMAGE_TAG) $(IMAGE_REPO)/$(IMAGE_NAME):latest
	@nerdctl push $(IMAGE_REPO)/$(IMAGE_NAME):$(IMAGE_TAG)
	@nerdctl push $(IMAGE_REPO)/$(IMAGE_NAME):latest
	@echo "Pushing the docker image for $(IMAGE_REPO)/$(GENERATOR_IMAGE_NAME):$(IMAGE_TAG) and $(IMAGE_REPO)/$(GENERATOR_IMAGE_NAME):latest..."
	@nerdctl tag $(IMAGE_REPO)/$(GENERATOR_IMAGE_NAME):$(IMAGE_TAG) $(IMAGE_REPO)/$(GENERATOR_IMAGE_NAME):latest
	@nerdctl push $(IMAGE_REPO)/$(GENERATOR_IMAGE_NAME):$(IMAGE_TAG)
	@nerdctl push $(IMAGE_REPO)/$(GENERATOR_IMAGE_NAME):latest


############################################################
# Docker image section
############################################################

docker-image: docker-login docker-build docker-push

docker-login:
	@echo "$(DOCKER_TOKEN)" | docker login -u "$(DOCKER_USER)" --password-stdin "$(REPOSITORY_BASE)"

docker-logout:
	@docker logout

docker-build:
	@echo "Building the docker image: $(IMAGE_REPO)/$(IMAGE_NAME):$(IMAGE_TAG)..."
	@docker build -t $(IMAGE_REPO)/$(IMAGE_NAME):$(IMAGE_TAG) -f build/Dockerfile .
	@echo "Building the docker image: $(IMAGE_REPO)/$(GENERATOR_IMAGE_NAME):$(IMAGE_TAG)..."
	@docker build -t $(IMAGE_REPO)/$(GENERATOR_IMAGE_NAME):$(IMAGE_TAG) -f build/Dockerfile.cert-generator .

docker-push: docker-build
	@echo "Pushing the docker image for $(IMAGE_REPO)/$(IMAGE_NAME):$(IMAGE_TAG) and $(IMAGE_REPO)/$(IMAGE_NAME):latest..."
	@docker tag $(IMAGE_REPO)/$(IMAGE_NAME):$(IMAGE_TAG) $(IMAGE_REPO)/$(IMAGE_NAME):latest
	@docker push $(IMAGE_REPO)/$(IMAGE_NAME):$(IMAGE_TAG)
	@docker push $(IMAGE_REPO)/$(IMAGE_NAME):latest
	@echo "Pushing the docker image for $(IMAGE_REPO)/$(GENERATOR_IMAGE_NAME):$(IMAGE_TAG) and $(IMAGE_REPO)/$(GENERATOR_IMAGE_NAME):latest..."
	@docker tag $(IMAGE_REPO)/$(GENERATOR_IMAGE_NAME):$(IMAGE_TAG) $(IMAGE_REPO)/$(GENERATOR_IMAGE_NAME):latest
	@docker push $(IMAGE_REPO)/$(GENERATOR_IMAGE_NAME):$(IMAGE_TAG)
	@docker push $(IMAGE_REPO)/$(GENERATOR_IMAGE_NAME):latest


############################################################
# clean section
############################################################
clean:
	@rm -rf build/_output

.PHONY: all fmt lint check test build docker-image containerd-image clean
