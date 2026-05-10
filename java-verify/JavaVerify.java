// java-verify is a small CLI that runs Java's PKIX CertPathValidator
// against a leaf, optional intermediates, and a trust anchor PEM file.
// It exists so test_nc_chains.py can include Java's built-in path
// validator among the validators it runs.
//
// Usage:
//
//     java-verify --ca ROOT [--intermediate FILE ...] [--at TIME] LEAF
//
// LEAF and the --intermediate / --ca files are PEM. A PEM file may
// contain multiple certificates; any extras in the LEAF file beyond
// the first are treated as intermediates.
//
// Exit codes:
//
//     0  - chain verified
//     1  - chain rejected by CertPathValidator
//     2  - usage error / I/O / parse error

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class JavaVerify {

    private static void usage() {
        System.err.println(
            "usage: java-verify --ca ROOT [--intermediate FILE ...] [--at TIME] LEAF");
    }

    private static List<X509Certificate> loadCerts(String path)
            throws IOException, CertificateException {
        try (InputStream in = new BufferedInputStream(Files.newInputStream(Path.of(path)))) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> certs = cf.generateCertificates(in);
            if (certs.isEmpty()) {
                throw new IOException(path + ": no PEM CERTIFICATE blocks found");
            }
            List<X509Certificate> out = new ArrayList<>(certs.size());
            for (Certificate c : certs) {
                out.add((X509Certificate) c);
            }
            return out;
        }
    }

    public static void main(String[] args) {
        String caFile = null;
        List<String> intermediateFiles = new ArrayList<>();
        String atStr = null;
        String leafFile = null;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--ca":
                    if (++i >= args.length) { usage(); System.exit(2); }
                    caFile = args[i];
                    break;
                case "--intermediate":
                    if (++i >= args.length) { usage(); System.exit(2); }
                    intermediateFiles.add(args[i]);
                    break;
                case "--at":
                    if (++i >= args.length) { usage(); System.exit(2); }
                    atStr = args[i];
                    break;
                case "--version":
                    // Path validation lives in the JDK's `java.security.cert`
                    // (sun.security.x509.NameConstraintsExtension etc.), so the
                    // effective implementation tracks the running JRE rather
                    // than anything we depend on. java.runtime.version pins
                    // the patch level (e.g. "21.0.4+7-LTS").
                    System.out.println(
                        "java-verify (Java " +
                        System.getProperty("java.runtime.version", System.getProperty("java.version", "?")) +
                        ", " + System.getProperty("java.vm.name", "?") + ")");
                    return;
                case "-h":
                case "--help":
                    usage();
                    System.exit(2);
                    return;
                default:
                    if (args[i].startsWith("-")) {
                        System.err.println("unknown flag: " + args[i]);
                        usage();
                        System.exit(2);
                    }
                    if (leafFile != null) {
                        System.err.println("only one LEAF argument allowed");
                        usage();
                        System.exit(2);
                    }
                    leafFile = args[i];
                    break;
            }
        }

        if (caFile == null || leafFile == null) {
            usage();
            System.exit(2);
            return;
        }

        List<X509Certificate> leafCerts;
        List<X509Certificate> rootCerts;
        List<X509Certificate> intermediates = new ArrayList<>();
        try {
            leafCerts = loadCerts(leafFile);
            rootCerts = loadCerts(caFile);
            for (int i = 1; i < leafCerts.size(); i++) {
                intermediates.add(leafCerts.get(i));
            }
            for (String f : intermediateFiles) {
                intermediates.addAll(loadCerts(f));
            }
        } catch (IOException | CertificateException e) {
            System.err.println("load: " + e.getMessage());
            System.exit(2);
            return;
        }

        Date verificationTime;
        if (atStr != null) {
            try {
                verificationTime = Date.from(OffsetDateTime.parse(atStr).toInstant());
            } catch (DateTimeParseException e) {
                System.err.println("bad --at value: " + atStr);
                System.exit(2);
                return;
            }
        } else {
            // 2030-01-01 00:00 UTC. Matches rust-verify and dotnet-verify so the
            // corpus's long-dated chains (notBefore 2026-01-01, notAfter
            // 2036-12-30) all fall inside their validity window without the
            // caller having to pass --at.
            verificationTime = Date.from(Instant.parse("2030-01-01T00:00:00Z"));
        }

        Set<TrustAnchor> anchors = new HashSet<>();
        for (X509Certificate r : rootCerts) {
            anchors.add(new TrustAnchor(r, null));
        }

        List<X509Certificate> pathCerts = new ArrayList<>();
        pathCerts.add(leafCerts.get(0));
        pathCerts.addAll(intermediates);

        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            CertPath path = cf.generateCertPath(pathCerts);

            PKIXParameters params = new PKIXParameters(anchors);
            params.setRevocationEnabled(false);
            params.setDate(verificationTime);

            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            validator.validate(path, params);
            System.out.println("verify ok");
        } catch (CertPathValidatorException e) {
            int idx = e.getIndex();
            String suffix = (idx >= 0) ? " (cert index " + idx + ")" : "";
            CertPathValidatorException.Reason reason = e.getReason();
            String reasonStr = (reason != null
                    && reason != CertPathValidatorException.BasicReason.UNSPECIFIED)
                ? " [" + reason + "]" : "";
            System.out.println("verify failed: " + e.getMessage() + reasonStr + suffix);
            System.exit(1);
        } catch (InvalidAlgorithmParameterException
                 | NoSuchAlgorithmException
                 | CertificateException e) {
            System.err.println("setup: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            System.exit(2);
        } catch (RuntimeException e) {
            // Sun's PKIX implementation throws e.g. UnsupportedOperationException
            // out of NameConstraintsExtension.verify() when it can't process a
            // GeneralName form (notably OtherName). Without catching, Java
            // prints the full stack trace and exits 1; the harness then
            // captures dozens of frames as a single chain's "output". Treat
            // these as a verdict of "rejected, with a brief reason" — the
            // exception class + message tells the reader what happened
            // without dragging in the stack frames.
            System.out.println(
                "verify failed: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            System.exit(1);
        }
    }
}
