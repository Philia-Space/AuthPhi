.PHONY: build run test clean

build:
	go build -o authphi ./...

run:
	go run main.go

test:
	go test -race -cover ./...

test-single:
	go test -run $(TEST) ./...

lint:
	golangci-lint run ./...

fmt:
	gofmt -w . && goimports -w .

clean:
	rm -f authphi
