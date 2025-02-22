﻿using Netezos.Utils;

namespace Netezos.Keys;

/// <summary>
///     Extended (hierarchical deterministic) private key
/// </summary>
public class HDKey
{
    private readonly byte[] _ChainCode;
    private HDPubKey? _HDPubKey;

    /// <summary>
    ///     Generates a new extended (hierarchical deterministic) private key
    /// </summary>
    /// <param name="kind">Elliptic curve kind</param>
    public HDKey(ECKind kind = ECKind.Ed25519)
    {
        Key = new Key(kind);
        _ChainCode = RNG.GetBytes(32);
    }

    internal HDKey(Key key, byte[] chainCode)
    {
        Key = key ?? throw new ArgumentNullException(nameof(key));
        _ChainCode = chainCode?.Copy() ?? throw new ArgumentNullException(nameof(chainCode));
        if (chainCode.Length != 32) throw new ArgumentException("Invalid chain code length", nameof(chainCode));
    }

    /// <summary>
    ///     Private key
    /// </summary>
    public Key Key { get; }

    /// <summary>
    ///     32 bytes of entropy added to the private key to enable deriving secure child keys
    /// </summary>
    public byte[] ChainCode => _ChainCode.Copy();

    /// <summary>
    ///     Public key
    /// </summary>
    public PubKey PubKey => Key.PubKey;

    /// <summary>
    ///     Extended (hierarchical deterministic) public key
    /// </summary>
    public HDPubKey HDPubKey => _HDPubKey ??= new HDPubKey(Key.PubKey, _ChainCode);

    /// <summary>
    ///     Public key hash
    /// </summary>
    public string Address => Key.Address;

    private Curve Curve => Key.Curve;
    private HDStandard HD => HDStandard.Slip10;
    private byte[] Data => Key.Data;

    /// <summary>
    ///     Derives an extended child key at the given index
    /// </summary>
    /// <param name="index">Index of the child key, starting from zero</param>
    /// <param name="hardened">If true, hardened derivation will be performed</param>
    /// <returns>Derived extended child key</returns>
    public HDKey Derive(int index, bool hardened = false)
    {
        var ind = HDPath.GetIndex(index, hardened);
        var (prvKey, chainCode) = HD.GetChildPrivateKey(Curve, Data, _ChainCode, ind);
        return new HDKey(new Key(prvKey, Curve.Kind), chainCode);
    }

    /// <summary>
    ///     Derives an extended child key at the given path relative to the current key
    /// </summary>
    /// <param name="path">HD key path string, formatted like m/44'/1729'/0/0'</param>
    /// <returns>Derived extended child key</returns>
    public HDKey Derive(string path)
    {
        return Derive(HDPath.Parse(path));
    }

    /// <summary>
    ///     Derives an extended child key at the given path relative to the current key
    /// </summary>
    /// <param name="path">HD key path</param>
    /// <returns>Derived extended child key</returns>
    public HDKey Derive(HDPath path)
    {
        if (path == null)
            throw new ArgumentNullException(nameof(path));

        if (!path.Any())
            return this;

        var prvKey = Data;
        var chainCode = _ChainCode;

        foreach (var ind in path)
            (prvKey, chainCode) = HD.GetChildPrivateKey(Curve, prvKey, chainCode, ind);

        return new HDKey(new Key(prvKey, Curve.Kind), chainCode);
    }

    /// <summary>
    ///     Signs an array of bytes
    /// </summary>
    /// <param name="bytes">Array of bytes to sign</param>
    /// <returns>Signature object</returns>
    public Signature Sign(byte[] bytes)
    {
        return Key.Sign(bytes);
    }

    /// <summary>
    ///     Signs a UTF-8 encoded string
    /// </summary>
    /// <param name="message">String to sign</param>
    /// <returns>Signature object</returns>
    public Signature Sign(string message)
    {
        return Key.Sign(message);
    }

    /// <summary>
    ///     Signs forged operation bytes with 0x03 prefix added
    /// </summary>
    /// <param name="bytes">Forged operation bytes</param>
    /// <returns>Signature object</returns>
    public Signature SignOperation(byte[] bytes)
    {
        return Key.SignOperation(bytes);
    }

    /// <summary>
    ///     Verifies a signature of the given array of bytes
    /// </summary>
    /// <param name="data">Original data bytes</param>
    /// <param name="signature">Signature to verify</param>
    /// <returns>True if the signature is valid, otherwise false</returns>
    public bool Verify(byte[] data, byte[] signature)
    {
        return Key.Verify(data, signature);
    }

    /// <summary>
    ///     Verifies a signature of the given message string
    /// </summary>
    /// <param name="message">Original message string</param>
    /// <param name="signature">Signature to verify</param>
    /// <returns>True if the signature is valid, otherwise false</returns>
    public bool Verify(string message, string signature)
    {
        return Key.Verify(message, signature);
    }

    #region static

    /// <summary>
    ///     Creates an extended (hierarchical deterministic) private key from the given private key and chain code
    /// </summary>
    /// <param name="key">Private key</param>
    /// <param name="chainCode">32 bytes of entropy to be added to the private key</param>
    /// <returns>Extended private key</returns>
    public static HDKey FromKey(Key key, byte[] chainCode)
    {
        return new HDKey(key, chainCode);
    }

    /// <summary>
    ///     Creates an extended (hierarchical deterministic) private key from the given BIP-39 mnemonic
    /// </summary>
    /// <param name="mnemonic">BIP-39 mnemonic sentence</param>
    /// <param name="passphrase">Passphrase. If not present, an empty string "" is used instead, according to the standard.</param>
    /// <param name="kind">Elliptic curve kind</param>
    /// <returns>Extended private key</returns>
    public static HDKey FromMnemonic(Mnemonic mnemonic, string passphrase = "", ECKind kind = ECKind.Ed25519)
    {
        if (mnemonic == null) throw new ArgumentNullException(nameof(mnemonic));
        var seed = mnemonic.GetSeed(passphrase);
        var key = FromSeed(seed, kind);
        return key;
    }

    /// <summary>
    ///     Creates an extended (hierarchical deterministic) private key from the given seed bytes
    /// </summary>
    /// <param name="seed">Seed bytes</param>
    /// <param name="kind">Elliptic curve kind</param>
    /// <returns>Extended private key</returns>
    public static HDKey FromSeed(byte[] seed, ECKind kind = ECKind.Ed25519)
    {
        if (seed == null) throw new ArgumentNullException(nameof(seed));
        var (prvKey, chainCode) = HDStandard.Slip10.GenerateMasterKey(Curve.FromKind(kind), seed);
        return new HDKey(new Key(prvKey, kind), chainCode);
    }

    #endregion
}