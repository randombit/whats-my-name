# Builds the differential-test verifier helpers (Go, Rust, .NET, Java, pyca,
# wolfSSL) into ./bin so test_nc_chains.py can find them in one place.
#
# `make`              builds all of them
# `make go-verify`    / rust-verify / dotnet-verify / java-verify /
#                     pyca-verify / wolfssl-verify  builds one
# `make clean`        removes ./bin and per-language build artefacts

BIN := bin

GO_SRCS      := $(wildcard go-verify/*.go) go-verify/go.mod
RUST_SRCS    := $(wildcard rust-verify/src/*.rs) rust-verify/Cargo.toml
DOTNET_SRCS  := $(wildcard dotnet-verify/*.cs) dotnet-verify/dotnet-verify.csproj
JAVA_SRCS    := $(wildcard java-verify/*.java) java-verify/java-verify
PYCA_SRCS    := pyca-verify/pyca-verify
WOLFSSL_SRCS := $(wildcard wolfssl-verify/*.c)

# wolfSSL build flags. Override on the command line if pkg-config isn't
# wired up for wolfssl (Arch ships libwolfssl without a .pc file in some
# versions). The default falls back to `-lwolfssl` on the system search
# path with no extra cflags.
WOLFSSL_CFLAGS ?= $(shell pkg-config --cflags wolfssl 2>/dev/null)
WOLFSSL_LIBS   ?= $(shell pkg-config --libs   wolfssl 2>/dev/null || echo -lwolfssl)

.PHONY: all clean go-verify rust-verify dotnet-verify java-verify pyca-verify wolfssl-verify

all: $(BIN)/go-verify $(BIN)/rust-verify $(BIN)/dotnet-verify $(BIN)/java-verify $(BIN)/pyca-verify $(BIN)/wolfssl-verify

go-verify:      $(BIN)/go-verify
rust-verify:    $(BIN)/rust-verify
dotnet-verify:  $(BIN)/dotnet-verify
java-verify:    $(BIN)/java-verify
pyca-verify:    $(BIN)/pyca-verify
wolfssl-verify: $(BIN)/wolfssl-verify

$(BIN):
	mkdir -p $@

$(BIN)/go-verify: $(GO_SRCS) | $(BIN)
	cd go-verify && go build -o ../$(BIN)/go-verify

$(BIN)/rust-verify: $(RUST_SRCS) | $(BIN)
	cd rust-verify && cargo build --release
	cp rust-verify/target/release/rust-verify $(BIN)/rust-verify

# `dotnet publish` drops the apphost (`dotnet-verify`) plus its sidecars
# (dotnet-verify.dll, *.runtimeconfig.json, *.deps.json) into $(BIN).
# The harness only invokes the apphost; the sidecars share its prefix so
# they don't collide with go-verify / rust-verify.
$(BIN)/dotnet-verify: $(DOTNET_SRCS) | $(BIN)
	dotnet publish dotnet-verify/dotnet-verify.csproj -c Release --nologo -o $(BIN)
	touch $@

# Builds JavaVerify.java into a runnable JAR alongside a shell launcher in
# $(BIN). The harness invokes bin/java-verify (the launcher), which execs
# `java -jar bin/java-verify.jar`. Class files are staged under
# java-verify/classes so the JAR doesn't carry build droppings.
$(BIN)/java-verify: $(JAVA_SRCS) | $(BIN)
	rm -rf java-verify/classes
	mkdir -p java-verify/classes
	javac -d java-verify/classes java-verify/JavaVerify.java
	jar --create --file=$(BIN)/java-verify.jar --main-class=JavaVerify -C java-verify/classes .
	cp java-verify/java-verify $(BIN)/java-verify
	chmod +x $(BIN)/java-verify

# pyca-verify is a plain Python script with no build step. We still drop a
# copy in $(BIN) so test_nc_chains.py finds it through the same resolution
# pattern (`./bin/<name>`) as the other helpers. The harness invokes it via
# `sys.executable` so the cryptography import resolves against whichever
# interpreter the harness itself is running under.
$(BIN)/pyca-verify: $(PYCA_SRCS) | $(BIN)
	cp pyca-verify/pyca-verify $(BIN)/pyca-verify
	chmod +x $(BIN)/pyca-verify

# Small C shim against libwolfssl's CertManager API. Distro builds of
# wolfSSL typically omit OPENSSL_EXTRA, so the shim uses wolfSSL's
# native API rather than the X509_STORE compatibility layer.
$(BIN)/wolfssl-verify: $(WOLFSSL_SRCS) | $(BIN)
	$(CC) $(CFLAGS) $(WOLFSSL_CFLAGS) -o $@ $(WOLFSSL_SRCS) $(WOLFSSL_LIBS)

clean:
	rm -rf $(BIN)
	-cd go-verify && go clean
	-cd rust-verify && cargo clean
	rm -rf dotnet-verify/bin dotnet-verify/obj
	rm -rf java-verify/classes
