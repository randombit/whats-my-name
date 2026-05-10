// Minimal emulation of openssl's `verify` subcommand using BoringSSL's PKI
// path builder.
//
// Usage:
//   verify -CAfile <root.pem> [-untrusted <intermediates.pem>]... <leaf.pem>
//
// All inputs are PEM. -untrusted may be passed multiple times; each file may
// contain one or more concatenated PEM certificates.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/pool.h>

#include "cert_errors.h"
#include "cert_issuer_source_static.h"
#include "certificate_policies.h"
#include "encode_values.h"
#include "input.h"
#include "parse_values.h"
#include "parsed_certificate.h"
#include "path_builder.h"
#include "pem.h"
#include "simple_path_builder_delegate.h"
#include "trust_store_in_memory.h"
#include "verify_certificate_chain.h"

namespace {

std::string ReadFile(const char *path, bool *ok) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    fprintf(stderr, "error: cannot open %s\n", path);
    *ok = false;
    return {};
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  *ok = true;
  return ss.str();
}

// Parses every CERTIFICATE PEM block in `path` and appends the resulting
// ParsedCertificates to `out`. Returns false (and prints to stderr) on any
// I/O or parse failure. Requires at least one certificate to be present.
bool ReadPemCerts(const char *path,
                  std::vector<std::shared_ptr<const bssl::ParsedCertificate>>
                      *out) {
  bool ok = false;
  std::string contents = ReadFile(path, &ok);
  if (!ok) {
    return false;
  }
  bssl::PEMTokenizer tokenizer(contents, {"CERTIFICATE"});
  size_t count = 0;
  while (tokenizer.GetNext()) {
    const std::string &der = tokenizer.data();
    bssl::UniquePtr<CRYPTO_BUFFER> buffer(CRYPTO_BUFFER_new(
        reinterpret_cast<const uint8_t *>(der.data()), der.size(), nullptr));
    if (buffer == nullptr) {
      fprintf(stderr, "error: out of memory parsing %s\n", path);
      return false;
    }
    bssl::CertErrors errors;
    auto parsed = bssl::ParsedCertificate::Create(std::move(buffer), {},
                                                  &errors);
    if (parsed == nullptr) {
      fprintf(stderr, "error: failed to parse certificate in %s:\n%s\n", path,
              errors.ToDebugString().c_str());
      return false;
    }
    out->push_back(std::move(parsed));
    count++;
  }
  if (count == 0) {
    fprintf(stderr, "error: no PEM CERTIFICATE blocks in %s\n", path);
    return false;
  }
  return true;
}

void Usage(const char *argv0) {
  fprintf(stderr,
          "usage: %s -CAfile <root.pem> [-untrusted <intermediates.pem>]... "
          "<leaf.pem>\n",
          argv0);
}

}  // namespace

int main(int argc, char **argv) {
  const char *ca_file = nullptr;
  const char *leaf_file = nullptr;
  std::vector<const char *> untrusted_files;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-CAfile") == 0 && i + 1 < argc) {
      ca_file = argv[++i];
    } else if (strcmp(argv[i], "-untrusted") == 0 && i + 1 < argc) {
      untrusted_files.push_back(argv[++i]);
    } else if (strcmp(argv[i], "--version") == 0 ||
               strcmp(argv[i], "-version") == 0) {
      // BoringSSL exposes its identity through OpenSSL_version(0); the
      // numeric form (OPENSSL_VERSION_NUMBER) is BoringSSL's compatibility
      // shim and not meaningful as a release tag. We append the libpki
      // path's path_builder TU identity so the printout is unambiguous.
      printf("boringssl-verify (%s)\n", OpenSSL_version(OPENSSL_VERSION));
      return 0;
    } else if (argv[i][0] == '-') {
      fprintf(stderr, "error: unknown option %s\n", argv[i]);
      Usage(argv[0]);
      return 2;
    } else if (leaf_file == nullptr) {
      leaf_file = argv[i];
    } else {
      fprintf(stderr, "error: unexpected positional argument %s\n", argv[i]);
      Usage(argv[0]);
      return 2;
    }
  }

  if (ca_file == nullptr || leaf_file == nullptr) {
    Usage(argv[0]);
    return 2;
  }

  std::vector<std::shared_ptr<const bssl::ParsedCertificate>> roots;
  std::vector<std::shared_ptr<const bssl::ParsedCertificate>> intermediates;
  std::vector<std::shared_ptr<const bssl::ParsedCertificate>> leaves;
  if (!ReadPemCerts(ca_file, &roots) ||
      !ReadPemCerts(leaf_file, &leaves)) {
    return 2;
  }
  for (const char *f : untrusted_files) {
    if (!ReadPemCerts(f, &intermediates)) {
      return 2;
    }
  }

  bssl::TrustStoreInMemory trust_store;
  for (const auto &root : roots) {
    trust_store.AddTrustAnchor(root);
  }

  bssl::CertIssuerSourceStatic issuer_source;
  for (const auto &cert : intermediates) {
    issuer_source.AddCert(cert);
  }

  bssl::der::GeneralizedTime now;
  if (!bssl::der::EncodePosixTimeAsGeneralizedTime(time(nullptr), &now)) {
    fprintf(stderr, "error: failed to encode current time\n");
    return 2;
  }

  bssl::SimplePathBuilderDelegate delegate(
      /*min_rsa_modulus_length_bits=*/1024,
      bssl::SimplePathBuilderDelegate::DigestPolicy::kStrong);

  std::set<bssl::der::Input> any_policy = {
      bssl::der::Input(bssl::kAnyPolicyOid)};
  bssl::CertPathBuilder path_builder(
      leaves.front(), &trust_store, &delegate, now, bssl::KeyPurpose::ANY_EKU,
      bssl::InitialExplicitPolicy::kFalse, any_policy,
      bssl::InitialPolicyMappingInhibit::kFalse,
      bssl::InitialAnyPolicyInhibit::kFalse);
  path_builder.AddCertIssuerSource(&issuer_source);

  bssl::CertPathBuilder::Result result = path_builder.Run();

  if (result.HasValidPath()) {
    printf("%s: OK\n", leaf_file);
    return 0;
  }

  bssl::VerifyError err = result.GetBestPathVerifyError();
  printf("%s: verification failed\n", leaf_file);
  printf("error: %s\n", err.DiagnosticString().c_str());
  return 1;
}
