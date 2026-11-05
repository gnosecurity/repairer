# One gate before anything ships: format, vet, unit tests, builds.
# The integration test needs root and a Linux kernel: make integration.
# The signing test needs gnokey and a test keybase: make golden (see below).
.PHONY: qa fmt vet test build integration golden

qa: fmt vet test build

# vendor/ holds decred's secp256k1, pinned and reviewed; it is checked as shipped.
fmt:
	@out=$$(gofmt -l admit agent approve cmd guard lookout nft policy scripts signer); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	go vet ./...
	go vet -tags integration ./...

test:
	go test -count=1 ./...

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/autopatch-agent-linux-amd64 ./cmd/autopatch-agent
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o bin/autopatch-agent-linux-arm64 ./cmd/autopatch-agent
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -o bin/autopatch-sign-darwin-arm64 ./cmd/autopatch-sign
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/autopatch-sign-linux-amd64 ./cmd/autopatch-sign
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/autopatch-lookout-linux-amd64 ./cmd/autopatch-lookout

integration:
	scripts/netns-test.sh

# The owner's tool signs every kind of statement with a real gnokey and a
# test keybase, and the agent's checks accept each one. Set GNOKEY_BIN,
# GNOKEY_HOME, GNOKEY_KEY (a public test key, "owner") and GNOKEY_PASSWORD.
# One package at a time: gnokey locks its keybase.
golden:
	go test -p 1 -count=1 -run 'TestGnokeyGolden|TestSignYes' ./signer/ ./cmd/autopatch-sign/
