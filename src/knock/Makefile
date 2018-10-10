GOPATH := ${CURDIR}/../../
export GOPATH

test:
	gofmt -d *.go
	go vet
	go test
