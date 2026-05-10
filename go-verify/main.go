// go-verify is a small CLI that runs Go's crypto/x509.Verify against a
// leaf, optional intermediates, and a trust anchor PEM file. It exists
// so test_nc_chains.py can include Go among the validators it runs.
//
// Usage:
//
//	go-verify -ca ROOT [-intermediate FILE ...] [-at TIME] LEAF
//
// LEAF and the -intermediate / -ca files are PEM. A PEM file may
// contain multiple certificates; any extras in the LEAF file beyond
// the first are treated as intermediates.
//
// Exit codes:
//
//	0  - chain verified
//	1  - chain rejected by x509.Verify
//	2  - usage error / I/O / parse error
package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"
)

type stringSlice []string

func (s *stringSlice) String() string     { return fmt.Sprint(*s) }
func (s *stringSlice) Set(v string) error { *s = append(*s, v); return nil }

func loadCerts(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []*x509.Certificate
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				// The path is supplied by the caller and echoed
				// verbatim by the differential harness, so we
				// don't add it here - just the parse error.
				return nil, err
			}
			out = append(out, c)
		}
		data = rest
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no PEM CERTIFICATE blocks found")
	}
	return out, nil
}

func main() {
	var caFile string
	var intermediateFiles stringSlice
	var atStr string
	var showVersion bool

	flag.StringVar(&caFile, "ca", "", "PEM file containing one or more trust anchors (required)")
	flag.Var(&intermediateFiles, "intermediate", "PEM file with intermediate cert(s); may be repeated")
	flag.StringVar(&atStr, "at", "", "Validation time in RFC3339 (default: now)")
	flag.BoolVar(&showVersion, "version", false, "Print the Go runtime version this binary was built against and exit")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: go-verify -ca ROOT [-intermediate FILE ...] [-at TIME] LEAF")
		flag.PrintDefaults()
	}
	flag.Parse()

	if showVersion {
		// crypto/x509 is part of the Go standard library, so the
		// effective name-constraints implementation tracks the Go
		// toolchain (runtime.Version()) rather than any pinned module.
		fmt.Printf("go-verify (Go %s, %s/%s)\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return
	}

	if caFile == "" || flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	leafCerts, err := loadCerts(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "load leaf: %v\n", err)
		os.Exit(2)
	}
	leaf := leafCerts[0]

	roots := x509.NewCertPool()
	rootCerts, err := loadCerts(caFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load CA: %v\n", err)
		os.Exit(2)
	}
	for _, c := range rootCerts {
		roots.AddCert(c)
	}

	intermediates := x509.NewCertPool()
	// Extra certs after the leaf in the LEAF file are intermediates.
	for _, c := range leafCerts[1:] {
		intermediates.AddCert(c)
	}
	for _, f := range intermediateFiles {
		cs, err := loadCerts(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load intermediate: %v\n", err)
			os.Exit(2)
		}
		for _, c := range cs {
			intermediates.AddCert(c)
		}
	}

	at := time.Now()
	if atStr != "" {
		t, err := time.Parse(time.RFC3339, atStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bad -at value: %v\n", err)
			os.Exit(2)
		}
		at = t
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   at,
		// Match other validators in the suite: don't constrain by EKU.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := leaf.Verify(opts); err != nil {
		fmt.Printf("verify failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("verify ok")
}
