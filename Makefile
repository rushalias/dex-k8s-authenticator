GOBIN=$(shell pwd)/bin
GOFILES=$(wildcard *.go)
GONAME=dex-k8s-authenticator
REPOSITORY=docker.otenv.com/${GONAME}
TAG=$(shell date +%Y%m%d%H%M%S)

all: build 

build:
	@echo "Building $(GOFILES) to ./bin"
	GOBIN=$(GOBIN) go build -o bin/$(GONAME) $(GOFILES)

container:
	@echo "Building container image"
	docker build -t ${REPOSITORY}:${TAG} .
	@echo "Push container image"
	docker push ${REPOSITORY}:${TAG}

clean:
	@echo "Cleaning"
	GOBIN=$(GOBIN) go clean
	rm -rf ./bin

.PHONY: build clean container
