# One gate before anything ships: format, vet, unit tests, builds.
# The integration test needs root and a Linux kernel: make integration.
.PHONY: qa fmt vet test build integration

qa: fmt vet test build

# vendor/ holds decred's secp256k1, pinned and reviewed; it is checked as shipped.
fmt:
	@out=$$(gofmt -l agent approve cmd guard nft policy); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	go vet ./...
	go vet -tags integration ./...

test:
	go test -count=1 ./...

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/autopatch-agent-linux-amd64 ./cmd/autopatch-agent
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o bin/autopatch-agent-linux-arm64 ./cmd/autopatch-agent

integration:
	scripts/netns-test.sh
