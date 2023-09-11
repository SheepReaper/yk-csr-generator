using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Yubico.YubiKey.Cryptography;
using Yubico.YubiKey.Piv;

using AlgConfig = (System.Security.Cryptography.HashAlgorithm digester, int algBits);

sealed class YubiKeySignatureGenerator : X509SignatureGenerator
{
    private static readonly Dictionary<HashAlgorithmName, AlgConfig> digesterMap = new()
    {
            {HashAlgorithmName.SHA1, (CryptographyProviders.Sha1Creator(),RsaFormat.Sha1)},
            {HashAlgorithmName.SHA256, (CryptographyProviders.Sha256Creator(),RsaFormat.Sha256)},
            {HashAlgorithmName.SHA384, (CryptographyProviders.Sha384Creator(),RsaFormat.Sha384)},
            {HashAlgorithmName.SHA512, (CryptographyProviders.Sha512Creator(),RsaFormat.Sha512)},
        };

    private readonly PivSession _pivSession;
    private readonly byte _slotNumber;
    private readonly int _keySizeBits;

    private readonly X509SignatureGenerator _defaultGenerator;
    private readonly RSASignaturePaddingMode _paddingMode;
    public YubiKeySignatureGenerator(PivSession pivSession, byte slotNumber, RSA rsaPublicKeyObject, RSASignaturePadding paddingScheme)
    {
        _pivSession = pivSession;
        _slotNumber = slotNumber;
        _keySizeBits = rsaPublicKeyObject.KeySize;
        _defaultGenerator = CreateForRSA(rsaPublicKeyObject, paddingScheme);
        _paddingMode = paddingScheme.Mode;
    }

    protected override PublicKey BuildPublicKey()
    {
        return _defaultGenerator.PublicKey;
    }
    public override byte[] GetSignatureAlgorithmIdentifier(HashAlgorithmName hashAlgorithm)
    {
        return _defaultGenerator.GetSignatureAlgorithmIdentifier(hashAlgorithm);
    }

    public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm)
    {
        var dataToSign = DigestData(data, hashAlgorithm);
        dataToSign = PadRsa(dataToSign, hashAlgorithm);

        return _pivSession.Sign(_slotNumber, dataToSign);
    }

    private static AlgConfig GetSupportedAlgConfig(HashAlgorithmName hashAlgorithm) => digesterMap.TryGetValue(hashAlgorithm, out var algConfig)
            ? algConfig
            : throw new ArgumentException("Unsupported Hash Algorithm", nameof(hashAlgorithm));

    private static byte[] DigestData(byte[] data, HashAlgorithmName hashAlgorithm)
    {
        var (digester, _) = GetSupportedAlgConfig(hashAlgorithm);

        var digest = new byte[digester.HashSize / 8];
        _ = digester.TransformFinalBlock(data, 0, data.Length);

        if (digester.Hash is null) throw new InvalidOperationException("Failure during hashing");

        Array.Copy(digester.Hash, 0, digest, 0, digest.Length);

        return digest;
    }

    private byte[] PadRsa(byte[] dataToSign, HashAlgorithmName hashAlgorithm)
    {
        var (_, rsaBits) = GetSupportedAlgConfig(hashAlgorithm);

        return _paddingMode == RSASignaturePaddingMode.Pkcs1
            ? RsaFormat.FormatPkcs1Sign(dataToSign, rsaBits, _keySizeBits)
            : RsaFormat.FormatPkcs1Pss(dataToSign, rsaBits, _keySizeBits);
    }
}
