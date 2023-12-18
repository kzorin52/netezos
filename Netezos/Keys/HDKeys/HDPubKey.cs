namespace Netezos.Keys;

/// <summary>
///     Extended (hierarchical deterministic) public key
/// </summary>
public class HDPubKey
{
    private readonly byte[] _ChainCode;

    internal HDPubKey(PubKey pubKey, byte[] chainCode)
    {
        PubKey = pubKey ?? throw new ArgumentNullException(nameof(pubKey));
        _ChainCode = chainCode?.Copy() ?? throw new ArgumentNullException(nameof(chainCode));
        if (chainCode.Length != 32) throw new ArgumentException("Invalid chain code length", nameof(chainCode));
    }

    /// <summary>
    ///     Public key
    /// </summary>
    public PubKey PubKey { get; }

    /// <summary>
    ///     Public key hash
    /// </summary>
    public string Address => PubKey.Address;

    /// <summary>
    ///     32 bytes of entropy added to the public key to enable deriving secure child keys
    /// </summary>
    public byte[] ChainCode => _ChainCode.Copy();

    private Curve Curve => PubKey.Curve;
    private HDStandard HD => HDStandard.Slip10;
    private byte[] Data => PubKey.Data;

    /// <summary>
    ///     Derives an extended child key at the given index
    /// </summary>
    /// <param name="index">Index of the child key, starting from zero</param>
    /// <param name="hardened">If true, hardened derivation will be performed</param>
    /// <returns>Derived extended child key</returns>
    public HDPubKey Derive(int index, bool hardened = false)
    {
        var ind = HDPath.GetIndex(index, hardened);
        var (pubKey, chainCode) = HD.GetChildPublicKey(Curve, Data, _ChainCode, ind);
        return new HDPubKey(new PubKey(pubKey, Curve.Kind), chainCode);
    }

    /// <summary>
    ///     Derives an extended child key at the given path relative to the current key
    /// </summary>
    /// <param name="path">HD key path string, formatted like m/44'/1729'/0/0'</param>
    /// <returns>Derived extended child key</returns>
    public HDPubKey Derive(string path)
    {
        return Derive(HDPath.Parse(path));
    }

    /// <summary>
    ///     Derives an extended child key at the given path relative to the current key
    /// </summary>
    /// <param name="path">HD key path</param>
    /// <returns>Derived extended child key</returns>
    public HDPubKey Derive(HDPath path)
    {
        if (path == null)
            throw new ArgumentNullException(nameof(path));

        if (!path.Any())
            return this;


        var pubKey = Data;
        var chainCode = _ChainCode;

        foreach (var ind in path)
            (pubKey, chainCode) = HD.GetChildPublicKey(Curve, pubKey, chainCode, ind);

        return new HDPubKey(new PubKey(pubKey, Curve.Kind), chainCode);
    }

    /// <summary>
    ///     Verifies a signature of the given array of bytes
    /// </summary>
    /// <param name="data">Original data bytes</param>
    /// <param name="signature">Signature to verify</param>
    /// <returns>True if the signature is valid, otherwise false</returns>
    public bool Verify(byte[] data, byte[] signature)
    {
        return PubKey.Verify(data, signature);
    }

    /// <summary>
    ///     Verifies a signature of the given message string
    /// </summary>
    /// <param name="message">Original message string</param>
    /// <param name="signature">Signature to verify</param>
    /// <returns>True if the signature is valid, otherwise false</returns>
    public bool Verify(string message, string signature)
    {
        return PubKey.Verify(message, signature);
    }

    #region static

    /// <summary>
    ///     Creates an extended (hierarchical deterministic) public key from the given public key and chain code
    /// </summary>
    /// <param name="pubKey">Public key</param>
    /// <param name="chainCode">32 bytes of entropy to be added to the public key</param>
    /// <returns>Extended public key</returns>
    public static HDPubKey FromPubKey(PubKey pubKey, byte[] chainCode)
    {
        return new HDPubKey(pubKey, chainCode);
    }

    #endregion
}