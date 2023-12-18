using Netezos.Encoding;
using Netezos.Utils;

namespace Netezos.Keys;

public class PubKey
{
    internal readonly Curve Curve;
    internal readonly byte[] Data;
    private string? _Address;

    internal PubKey(in byte[] bytes, ECKind kind)
    {
        if ((kind == ECKind.Ed25519 && bytes.Length != 32) ||
            (kind == ECKind.Secp256k1 && bytes.Length != 33) ||
            (kind == ECKind.NistP256 && bytes.Length != 33) ||
            (kind == ECKind.Bls12381 && bytes.Length != 48))
            throw new ArgumentException("Invalid public key length", nameof(bytes));

        Curve = Curve.FromKind(kind);
        Data = bytes;
    }

    public string Address
    {
        get { return _Address ??= Base58.Convert(Blake2b.GetDigest(Data, 160), Curve.AddressPrefix); }
    }

    public byte[] GetBytes()
    {
        return Data;
    }

    public string GetBase58()
    {
        return Base58.Convert(Data, Curve.PublicKeyPrefix);
    }

    public string GetHex()
    {
        return Hex.Convert(Data);
    }

    public bool Verify(byte[] data, byte[] signature)
    {
        return Curve.Verify(data, signature, Data);
    }

    public bool Verify(byte[] data, string signature)
    {
        return Base58.TryParse(signature, Curve.SignaturePrefix, out var signatureBytes)
               && Curve.Verify(data, signatureBytes, Data);
    }

    public bool Verify(string message, string signature)
    {
        return Utf8.TryParse(message, out var messageBytes)
               && Base58.TryParse(signature, Curve.SignaturePrefix, out var signatureBytes)
               && Curve.Verify(messageBytes, signatureBytes, Data);
    }

    public override string ToString()
    {
        return GetBase58();
    }

    #region static

    public static PubKey FromBytes(byte[] bytes, ECKind kind = ECKind.Ed25519)
    {
        return new PubKey(bytes, kind);
    }

    public static PubKey FromHex(string hex, ECKind kind = ECKind.Ed25519)
    {
        return new PubKey(Hex.Parse(hex), kind);
    }

    public static PubKey FromBase64(string base64, ECKind kind = ECKind.Ed25519)
    {
        return new PubKey(Base64.Parse(base64), kind);
    }

    public static PubKey FromBase58(string base58)
    {
        var curve = Curve.FromPublicKeyBase58(base58);
        var bytes = Base58.Parse(base58, curve.PublicKeyPrefix);

        return new PubKey(bytes, curve.Kind);
    }

    #endregion
}