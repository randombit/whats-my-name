// dotnet-verify is a small CLI that runs .NET's X509Chain against a
// leaf, optional intermediates, and a trust anchor PEM file. It exists
// so test_nc_chains.py can include .NET among the validators it runs.
//
// Usage:
//
//     dotnet-verify --ca ROOT [--intermediate FILE ...] [--at TIME] LEAF
//
// LEAF and the --intermediate / --ca files are PEM. A PEM file may
// contain multiple certificates; any extras in the LEAF file beyond
// the first are treated as intermediates.
//
// Exit codes:
//
//     0  - chain verified
//     1  - chain rejected by X509Chain.Build
//     2  - usage error / I/O / parse error

using System.Globalization;
using System.Security.Cryptography.X509Certificates;

static void Usage()
{
    Console.Error.WriteLine(
        "usage: dotnet-verify --ca ROOT [--intermediate FILE ...] [--at TIME] LEAF");
}

static X509Certificate2Collection LoadCerts(string path)
{
    var col = new X509Certificate2Collection();
    col.ImportFromPemFile(path);
    if (col.Count == 0)
    {
        throw new InvalidOperationException(
            $"{path}: no CERTIFICATE PEM blocks found");
    }
    return col;
}

string? caFile = null;
var intermediateFiles = new List<string>();
string? atStr = null;
string? leafFile = null;

for (int i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--ca":
            if (++i >= args.Length) { Usage(); return 2; }
            caFile = args[i];
            break;
        case "--intermediate":
            if (++i >= args.Length) { Usage(); return 2; }
            intermediateFiles.Add(args[i]);
            break;
        case "--at":
            if (++i >= args.Length) { Usage(); return 2; }
            atStr = args[i];
            break;
        case "--version":
            // .NET's path-validation is in the runtime (System.Security.Cryptography);
            // it tracks Environment.Version (the loaded runtime), not the SDK we
            // built against. RuntimeInformation.FrameworkDescription includes the
            // patch level (e.g. ".NET 8.0.11").
            Console.WriteLine(
                "dotnet-verify (" +
                System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription +
                ", runtime " + Environment.Version + ")");
            return 0;
        case "-h":
        case "--help":
            Usage();
            return 2;
        default:
            if (args[i].StartsWith('-'))
            {
                Console.Error.WriteLine($"unknown flag: {args[i]}");
                Usage();
                return 2;
            }
            if (leafFile != null)
            {
                Console.Error.WriteLine("only one LEAF argument allowed");
                Usage();
                return 2;
            }
            leafFile = args[i];
            break;
    }
}

if (caFile is null || leafFile is null)
{
    Usage();
    return 2;
}

X509Certificate2Collection leafCerts;
X509Certificate2Collection rootCerts;
var intermediates = new X509Certificate2Collection();
try
{
    leafCerts = LoadCerts(leafFile);
    rootCerts = LoadCerts(caFile);
    for (int i = 1; i < leafCerts.Count; i++)
    {
        intermediates.Add(leafCerts[i]);
    }
    foreach (var f in intermediateFiles)
    {
        foreach (var c in LoadCerts(f))
        {
            intermediates.Add(c);
        }
    }
}
catch (Exception ex)
{
    Console.Error.WriteLine($"load: {ex.Message}");
    return 2;
}

DateTime verificationTime;
if (atStr is not null)
{
    if (!DateTime.TryParse(
            atStr,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal,
            out verificationTime))
    {
        Console.Error.WriteLine($"bad --at value: {atStr}");
        return 2;
    }
}
else
{
    // 2030-01-01 00:00 UTC. Matches rust-verify so the corpus's long-dated
    // chains (notBefore 2026-01-01, notAfter 2036-12-30) all fall inside
    // their validity window without needing the caller to pass --at.
    verificationTime = new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc);
}

using var chain = new X509Chain();
chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
foreach (var r in rootCerts)
{
    chain.ChainPolicy.CustomTrustStore.Add(r);
}
chain.ChainPolicy.ExtraStore.AddRange(intermediates);
chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
chain.ChainPolicy.VerificationTime = verificationTime;
// ApplicationPolicy is left empty (no required EKU) to match the
// other validators in the suite, mirroring Go's ExtKeyUsageAny.

bool ok = chain.Build(leafCerts[0]);
if (ok)
{
    Console.WriteLine("verify ok");
    return 0;
}

var statuses = chain.ChainStatus
    .Select(s => $"{s.Status}: {s.StatusInformation.Trim()}")
    .ToArray();
Console.WriteLine(
    "verify failed: " +
    (statuses.Length == 0 ? "(no chain status)" : string.Join("; ", statuses)));
return 1;
