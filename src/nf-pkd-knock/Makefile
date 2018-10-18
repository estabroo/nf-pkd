GOPATH := ${CURDIR}/../../
export GOPATH

SRC := nf-pkd-knock.go ../knock/knock.go

all: nf-pkd-knock

vendor:
	dep init

Gopkg.toml: ${SRC}
	dep ensure

nf-pkd-knock: vendor Gopkg.toml ${SRC}
	gofmt -l *.go
	go vet
	go build

test:
	go test

clean:
	rm -f coverage.out nf-pkd-knock
