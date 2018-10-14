GOPATH := ${CURDIR}/../../
export GOPATH

SRC := nf-pkd.go action.go flow.go packet.go ../knock/knock.go

all: nf-pkd

vendor:
	dep init

Gopkg.toml: ${SRC}
	dep ensure

nf-pkd: vendor Gopkg.toml ${SRC}
	gofmt -l *.go
	go vet
	go build

test:
	go test
