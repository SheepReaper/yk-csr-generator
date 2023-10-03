using System.CommandLine;
using System.CommandLine.Binding;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Yubico.YubiKey;
using Yubico.YubiKey.Piv;

namespace GenerateYKCSR;


public static class GenerateCSRCommand
{
    public class Params
    {
        public IEnumerable<string> SanDns { get; set; } = new List<string>();
        public IEnumerable<string> SanEmail { get; set; } = new List<string>();
        public IEnumerable<IPAddress> SanIp { get; set; } = new List<IPAddress>();
        public IEnumerable<Uri> SanUri { get; set; } = new List<Uri>();
        public IEnumerable<string> SanUserPrincipalName { get; set; } = new List<string>();
        public bool RecreatePrivateKey { get; set; }
        public bool OutputToConsole { get; set; }
        public bool OutputPubToConsole { get; set; }
        public byte SlotNumber { get; set; }
        public HashAlgorithmName HashAlgorithmName { get; set; }
        public FileInfo? OutFile { get; set; }
        public FileInfo? OutPubFile { get; set; }
        public string? CommonName { get; set; }
        public string? CountryOrRegion { get; set; }
        public string? DomainComponent { get; set; }
        public string? Email { get; set; }
        public string? Locality { get; set; }
        public string? OrganizationalUnit { get; set; }
        public string? Organization { get; set; }
        public string? StateOrProvince { get; set; }
    }
    private static readonly byte[] _signingSlots = [130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 154, 156, 157, 158];
    private static IEnumerable<string> SlotHexStrings => Convert.ToHexString(_signingSlots).Chunk(2).Select((chars) => $"{chars[0]}{chars[1]}");
    private static IEnumerable<string> SlotStrings => _signingSlots.Select(s => ((int)s).ToString());
    private static readonly Dictionary<string, HashAlgorithmName> _supportedHashAlgos = new() {
        { "1.3.14.3.2.26", HashAlgorithmName.SHA1 },
        { "2.16.840.1.101.3.4.2.1", HashAlgorithmName.SHA256 },
        { "2.16.840.1.101.3.4.2.2", HashAlgorithmName.SHA384 },
        { "2.16.840.1.101.3.4.2.3", HashAlgorithmName.SHA512 }
    };
    private static IEnumerable<string> SupportedHashAlgoStrings => [.. _supportedHashAlgos.Values.Select(h => h.Name!), .. _supportedHashAlgos.Values.Select(h => h.Name!.ToLowerInvariant()), .. _supportedHashAlgos.Keys];
    public static readonly List<OptionMapper> Options = [
        new OptionMapper<bool>(new(
            aliases: ["--new-pk", "--replace-private-key"],
            description: "Indicates whether to replace the existing private key in the slot. If specified or set to true, a new private key will be generated.",
            getDefaultValue: () => false
        ), (o, v) => o.RecreatePrivateKey = v),
        new OptionMapper<string>(new Option<string>(
            aliases: ["--slot", "--slot-number"],
            description: "The slot number on the YubiKey device to be used for the key generation or retrieval.",
            getDefaultValue: () => PivSlot.KeyManagement.ToString("X2")).FromAmong([.. SlotHexStrings]
        ), (o, v) => o.SlotNumber = Convert.ToByte(v, 16)),
        new OptionMapper<FileInfo?>(new(
            aliases: ["--out", "--out-file"],
            description: "The file path where the generated CSR will be written. If not provided, CSR will be printed to the console."
        ), (o, v) => o.OutFile = v),
        new OptionMapper<FileInfo?>(new(
            aliases: ["--out-pub", "--out-pub-file"],
            description: "If specified, the file path where the public key extracted from the CSR will be written."
        ), (o, v) => o.OutPubFile = v),
        new OptionMapper<bool>(new(
            aliases: ["--text"],
            description: "Print CSR to console irrespective of file output option.",
            getDefaultValue: () => false
        ), (o, v) => o.OutputToConsole = v),
        new OptionMapper<bool>(new(
            aliases: ["--text-pub"],
            description: "Print the public key to the console.",
            getDefaultValue: () => false
        ), (o, v) => o.OutputPubToConsole = v),
        new OptionMapper<string>(new Option<string>(
            aliases: ["--hash"],
            description: "Specifies the hash algorithm to use for the CSR. Supported hash algorithms are SHA1, SHA256, SHA384, and SHA512. OIDs and friendly names (case-insensitive) of the algorithms can be used.",
            getDefaultValue: () => HashAlgorithmName.SHA256.Name!).FromAmong([.. SupportedHashAlgoStrings]
        ), (o, v) => o.HashAlgorithmName = _supportedHashAlgos.TryGetValue(v!, out var algoName) ? algoName : HashAlgorithmName.FromOid(Oid.FromFriendlyName(v!, OidGroup.HashAlgorithm).Value!)),
        new OptionMapper<string?>(new(
            aliases: ["--cn", "--common-name"],
            description: "The Common Name (CN) attribute to be included in the CSR's Distinguished Name (DN)."
        ), (o, v) => o.CommonName = v),
        new OptionMapper<string?>(new(
            aliases: ["--c", "--country", "--region"],
            description: "The Country or Region (C) attribute for the CSR's DN."
        ), (o, v) => o.CountryOrRegion = v),
        new OptionMapper<string?>(new(
            aliases: ["--dc", "--domain-component"],
            description: "The Domain Component (DC) attribute for the CSR's DN."
        ), (o, v) => o.DomainComponent = v),
        new OptionMapper<string?>(new(
            aliases: ["--e", "--email"],
            description: "The Email Address (E) attribute for the CSR's DN."
        ), (o, v) => o.Email = v),
        new OptionMapper<string?>(new(
            aliases: ["--l", "--locality", "--city"],
            description: "The Locality (L) attribute for the CSR's DN, typically represents the city or locality."
        ), (o, v) => o.Locality = v),
        new OptionMapper<string?>(new(
            aliases: ["--ou", "--organizational-unit"],
            description: "The Organizational Unit (OU) attribute for the CSR's DN, typically represents the department within an organization."
        ), (o, v) => o.OrganizationalUnit = v),
        new OptionMapper<string?>(new(
            aliases: ["--o", "--organization"],
            description: "The Organization (O) attribute for the CSR's DN."
        ), (o, v) => o.Organization = v),
        new OptionMapper<string?>(new(
            aliases: ["--st", "--state", "--province"],
            description: "The State or Province (ST) attribute for the CSR's DN."
        ), (o, v) => o.StateOrProvince = v),
        new OptionMapper<IEnumerable<string>>(new(
            aliases: ["--s-dns", "--san-dns"],
            description: "[Multiple] DNS name to be added to the Subject Alternative Name (SAN) extension.",
            getDefaultValue: () => new List<string>()
        ), (o, v) => o.SanDns = v ?? new List<string>()),
        new OptionMapper<IEnumerable<string>>(new(
            aliases: ["--s-e", "--san-email"],
            description: "[Multiple] Email address to be added to the SAN extension.",
            getDefaultValue: () => new List<string>()
        ), (o, v) => o.SanEmail = v ?? new List<string>()),
        new OptionMapper<IEnumerable<IPAddress>>(new(
            aliases: ["--s-ip", "--san-ip"],
            description: "[Multiple] IP address to be added to the SAN extension.",
            getDefaultValue: () => new List<IPAddress>()
        ), (o, v) => o.SanIp = v ?? new List<IPAddress>()),
        new OptionMapper<IEnumerable<Uri>>(new(
            aliases: ["--s-uri", "--san-uri"],
            description: "[Multiple] URI to be added to the SAN extension.",
            getDefaultValue: () => new List<Uri>()
        ), (o, v) => o.SanUri = v ?? new List<Uri>()),
        new OptionMapper<IEnumerable<string>>(new(
            aliases: ["--s-upn", "--san-user-principal-name"],
            description: "[Multiple] User Principal Name (UPN) to be added to the SAN extension.",
            getDefaultValue: () => new List<string>()
        ), (o, v) => o.SanUserPrincipalName = v ?? new List<string>()),
    ];

    public abstract class OptionMapper
    {
        public abstract Option Option { get; }
        public abstract void Bind(Params obj, BindingContext ctx);
    }

    public class OptionMapper<T>(Option<T> option, Action<Params, T?> propSetter) : OptionMapper
    {
        public override Option Option => option;

        public override void Bind(Params obj, BindingContext ctx)
        {
            propSetter(obj, ctx.ParseResult.GetValueForOption(option));
        }
    }

    public class Binder(params OptionMapper[] options) : BinderBase<Params>
    {
        readonly IEnumerable<OptionMapper> _options = options;

        protected override Params GetBoundValue(BindingContext bindingContext)
        {
            var obj = new Params();

            foreach (var opt in _options)
            {
                opt.Bind(obj, bindingContext);
            }

            return obj;
        }
    }

    public static async Task ExecuteAsync(Params boundParams)
    {
        if (!PivSlot.IsValidSlotNumberForSigning(boundParams.SlotNumber)) throw new InvalidOperationException("The requested slot is not capable of signing. Aborting...");

        X509Extension? sanExt = null;

        // TODO: Add custom OID support
        var dnBuilder = new X500DistinguishedNameBuilder();

        if (boundParams.CommonName is not null) dnBuilder.AddCommonName(boundParams.CommonName);
        if (boundParams.CountryOrRegion is not null) dnBuilder.AddCountryOrRegion(boundParams.CountryOrRegion);
        if (boundParams.DomainComponent is not null) dnBuilder.AddDomainComponent(boundParams.DomainComponent);
        if (boundParams.Email is not null) dnBuilder.AddEmailAddress(boundParams.Email);
        if (boundParams.Locality is not null) dnBuilder.AddLocalityName(boundParams.Locality);
        if (boundParams.OrganizationalUnit is not null) dnBuilder.AddOrganizationalUnitName(boundParams.OrganizationalUnit);
        if (boundParams.Organization is not null) dnBuilder.AddOrganizationName(boundParams.Organization);
        if (boundParams.StateOrProvince is not null) dnBuilder.AddStateOrProvinceName(boundParams.StateOrProvince);

        if (boundParams.SanDns.Any() || boundParams.SanEmail.Any() || boundParams.SanIp.Any() || boundParams.SanUri.Any() || boundParams.SanUserPrincipalName.Any())
        {
            var sanBuilder = new SubjectAlternativeNameBuilder();

            boundParams.SanDns.ToList().ForEach(sanBuilder.AddDnsName);
            boundParams.SanEmail.ToList().ForEach(sanBuilder.AddEmailAddress);
            boundParams.SanIp.ToList().ForEach(sanBuilder.AddIpAddress);
            boundParams.SanUri.ToList().ForEach(sanBuilder.AddUri);
            boundParams.SanUserPrincipalName.ToList().ForEach(sanBuilder.AddUserPrincipalName);

            sanExt = sanBuilder.Build();
        }

        var dn = dnBuilder.Build();

        var devices = YubiKeyDevice.FindAll();

        if (!devices.Any()) throw new InvalidOperationException("No YubiKeys were detected.");

        if (devices.Count() >= 2) throw new InvalidOperationException("Too many YubiKeys are plugged in. Leave only one plugged in and try again.");

        using var pivSession = new PivSession(devices.First()) { KeyCollector = YubiKeyKeyCollector.KeyCollectorDelegate };

        var rsaPublic = (PivRsaPublicKey)pivSession.GetMetadata(boundParams.SlotNumber).PublicKey;

        if (rsaPublic is null || boundParams.RecreatePrivateKey)
        {
            rsaPublic = (PivRsaPublicKey)pivSession.GenerateKeyPair(boundParams.SlotNumber, PivAlgorithm.Rsa2048);
        }

        var rsaParams = new RSAParameters
        {
            Modulus = rsaPublic.Modulus.ToArray(),
            Exponent = rsaPublic.PublicExponent.ToArray(),
        };

        var pko = RSA.Create(rsaParams);

        var sigGenerator = new YubiKeySignatureGenerator(pivSession, boundParams.SlotNumber, pko, RSASignaturePadding.Pss);

        var csr = new CertificateRequest(dn, pko, boundParams.HashAlgorithmName, RSASignaturePadding.Pss);

        if (sanExt is not null) csr.CertificateExtensions.Add(sanExt);

        var stringResult = csr.CreateSigningRequestPem(sigGenerator);

        if (boundParams.OutFile is not null) await File.WriteAllTextAsync(boundParams.OutFile.FullName, stringResult);

        if (boundParams.OutputToConsole || boundParams.OutFile is null) Console.WriteLine(stringResult.ReplaceLineEndings());

        var pub = csr.PublicKey.ExportSubjectPublicKeyInfo();

        string pubKeyPem =
            "-----BEGIN PUBLIC KEY-----\n" +
            Convert.ToBase64String(pub, Base64FormattingOptions.InsertLineBreaks) +
            "\n-----END PUBLIC KEY-----";

        if (boundParams.OutPubFile is not null) await File.WriteAllTextAsync(boundParams.OutPubFile.FullName, pubKeyPem);

        if (boundParams.OutputPubToConsole || boundParams.OutPubFile is null) Console.WriteLine(pubKeyPem.ReplaceLineEndings());
    }
}
