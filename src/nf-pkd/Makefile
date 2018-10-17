GOPATH := ${CURDIR}/../../
export GOPATH
VERSION := $(shell git describe)
ifndef VERSION
	VERSION = beta
endif

SRC := $(wildcard *.go) ../knock/knock.go

all: nf-pkd

vendor:
	dep init

Gopkg.toml: ${SRC}
	dep ensure

nf-pkd: vendor Gopkg.toml ${SRC}
	gofmt -l *.go
	go vet
	go test
	go build -ldflags "-X main.Version=$(VERSION)"

clean:
	rm coverage.out

test:
	go test

coverage.out: ${SRC}
	go test --cover --coverprofile=coverage.out

coverage: coverage.out
	go tool cover -html=coverage.out
