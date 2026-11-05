# One gate before anything ships: format, vet, unit tests, builds.
# The integration test needs root and a Linux kernel: make integration.
# The signing test needs gnokey and a test keybase: make golden (see below).
.PHONY: qa fmt vet test build integration golden gnotest site-e2e lookout-browser realm-e2e realm-e2e-gnoland

qa: fmt vet test build

# vendor/ holds decred's secp256k1, pinned and reviewed; it is checked as shipped.
# gofmt reads the .gno files too: gno is Go's syntax.
fmt:
	@out=$$(gofmt -l admit agent approve cmd gnosh guard lookout nft policy scripts signer $$(find gno -name '*.gno')); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

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
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/autopatch-gnosh-linux-amd64 ./cmd/autopatch-gnosh
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/autopatch-rig-linux-amd64 ./cmd/autopatch-rig
	CGO_ENABLED=0 GOOS=openbsd GOARCH=amd64 go build -trimpath -o bin/autopatch-site-openbsd-amd64 ./cmd/autopatch-site

integration:
	scripts/netns-test.sh

# The owner's tool signs every kind of statement with a real gnokey and a
# test keybase, and the agent's checks accept each one. Set GNOKEY_BIN,
# GNOKEY_HOME, GNOKEY_KEY (a public test key, "owner") and GNOKEY_PASSWORD.
# One package at a time: gnokey locks its keybase.
golden:
	go test -p 1 -count=1 -run 'TestGnokeyGolden|TestSignYes' ./signer/ ./cmd/autopatch-sign/

# The beacon package and the Guards realm, with gno built at the pinned
# commit 5d7d8f5f9: set GNO_BIN, and GNOROOT to its source (for the examples).
# Then every mutant of the realm in scripts/guards-mutants.py must fail.
gnotest:
	cd gno/p/drandbn254 && GNOROOT=$(GNOROOT) $(GNO_BIN) test .
	cd gno/r/guards && GNOROOT=$(GNOROOT) $(GNO_BIN) test -v -print-runtime-metrics .
	GNO_BIN=$(GNO_BIN) GNOROOT=$(GNOROOT) python3 scripts/guards-mutants.py gno

# gno.security's guard pages from the realm on a local chain: GNO_BIN_DIR holds
# gnodev and gnokey built from gno 5d7d8f5f9, GNOROOT its source.
site-e2e:
	GNOROOT=$(GNOROOT) scripts/site-e2e.sh $(GNO_BIN_DIR)

# The Guards realm on a local chain, end to end, with drand evmnet's real
# rounds (read from api.drand.sh): stake, file, draw, check, agree, finalize,
# the level param, a withdrawal; prints the gas each call used.
realm-e2e:
	GNOROOT=$(GNOROOT) scripts/realm-e2e.sh $(GNO_BIN_DIR)

# The same on a gnoland node making a block every 3.5 seconds, as gno.land does.
realm-e2e-gnoland:
	NODE=gnoland GNOROOT=$(GNOROOT) scripts/realm-e2e.sh $(GNO_BIN_DIR)

# The lookout's page in headless Chrome with a stand-in Adena: sign-in, the
# cookie, upload, downloads, sign-out ending every session, and the refusals,
# with no console errors. Needs node and puppeteer (NODE_PATH to its
# node_modules); OUT is where the screenshots go. Run before any deploy.
OUT ?= /tmp/lookout-shots
lookout-browser:
	CGO_ENABLED=0 go build -o /tmp/autopatch-lookout-browser ./cmd/autopatch-lookout
	node scripts/lookout-browser.js /tmp/autopatch-lookout-browser $(OUT)
