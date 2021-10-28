.PHONY: all
all: build test clean docker docker-push
.DEFAULT_GOAL:= build
# CGO_FLAGS = "-I/usr/lib/bcc/include/ -I/lib/modules/5.11.0-37-generic/build/include -I/usr/include/bpfs"

build:
	go build -o main main.go

test:
	go test ./...

docker:
	docker build -t bpf-challenge .

docker-push:
	echo "Not implemented ;P"

clean:
	rm main
	go clean -testcache