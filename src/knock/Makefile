GOPATH := ${CURDIR}/../../
export GOPATH

SRCS := $(wildcard *.go)
test:
	gofmt -d *.go
	go vet
	go test

clean:
	rm coverage.out

coverage.out: ${SRCS}
	go test --cover --coverprofile=coverage.out

coverage: coverage.out
	go tool cover -html=coverage.out
