﻿using System.ComponentModel;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Netezos.Utils;

namespace Netezos.Keys
{
    class Slip10 : HDStandard
    {
        public override (byte[], byte[]) GenerateMasterKey(Curve curve, byte[] seed)
        {
            if (curve.Kind == ECKind.Bls12381)
                throw new NotSupportedException("BLS12-381 curve is not supported by the SLIP-0010 standard");

            using var hmacSha512 = new HMACSHA512(curve.Slip10Seed);
            while (true)
            {
                var l = hmacSha512.ComputeHash(seed);
                var ll = l.GetBytes(0, 32);
                var lr = l.GetBytes(32, 32);

                if (curve.Kind == ECKind.Ed25519)
                {
                    return (ll, lr);
                }

                var parse256LL = new BigInteger(1, ll);
                var N = curve.Kind switch
                {
                    ECKind.Secp256k1 => Secp256k1.Curve.N,
                    ECKind.NistP256 => NistP256.Curve.N,
                    _ => throw new InvalidEnumArgumentException()
                };
                
                if (parse256LL.CompareTo(N) < 0 && parse256LL.CompareTo(BigInteger.Zero) != 0)
                {
                    return (ll, lr);
                }

                seed = l;
            }
        }

        public override (byte[], byte[]) GetChildPrivateKey(Curve curve, byte[] privateKey, byte[] chainCode, uint index)
        {
            if (curve.Kind == ECKind.Bls12381)
                throw new NotSupportedException("BLS12-381 curve is not supported by the SLIP-0010 standard");

            byte[] l;
            
            if ((index & 0x80000000) != 0) // hardened
            {
                l = Bip32Hash(chainCode, index, 0, privateKey);
            }
            else
            {
                if (curve.Kind == ECKind.Ed25519)
                    throw new NotSupportedException("Ed25519 doesn't support non-hardened key derivation");

                l = Bip32Hash(chainCode, index, curve.GetPublicKey(privateKey));
            }

            var ll = l.GetBytes(0, 32);
            var lr = l.GetBytes(32, 32);

            if (curve.Kind == ECKind.Ed25519)
            {
                return (ll, lr);
            }

            while (true)
            {
                var parse256LL = new BigInteger(1, ll);
                var kPar = new BigInteger(1, privateKey);
                var N = curve.Kind switch
                {
                    ECKind.Secp256k1 => Secp256k1.Curve.N,
                    ECKind.NistP256 => NistP256.Curve.N,
                    _ => throw new InvalidEnumArgumentException()
                };
                var key = parse256LL.Add(kPar).Mod(N);

                if (parse256LL.CompareTo(N) >= 0 || key.CompareTo(BigInteger.Zero) == 0)
                {
                    l = Bip32Hash(chainCode, index, 1, lr);
                    ll = l.GetBytes(0, 32);
                    lr = l.GetBytes(32, 32);
                    continue;
                }

                var keyBytes = key.ToByteArrayUnsigned();
                if (keyBytes.Length < 32)
                {
                    var kb = keyBytes;
                    keyBytes = new byte[32 - kb.Length].Concat(kb);
                }

                return (keyBytes, lr);
            }
        }

        public override (byte[], byte[]) GetChildPublicKey(Curve curve, byte[] pubKey, byte[] chainCode, uint index)
        {
            if (curve.Kind == ECKind.Bls12381)
                throw new NotSupportedException("BLS12-381 curve is not supported by the SLIP-0010 standard");

            if (curve.Kind == ECKind.Ed25519)
                throw new NotSupportedException("Ed25519 public key derivation not supported by slip-10");
            
            if (pubKey.Length != 33)
                throw new NotSupportedException("Invalid public key size (expected 33 bytes)");
            
            if ((index & 0x80000000) != 0)
                throw new InvalidOperationException("Can't derive a hardened child key from a public key");

            var c = curve.Kind switch
            {
                ECKind.Secp256k1 => Secp256k1.Curve,
                ECKind.NistP256 => NistP256.Curve,
                _ => throw new InvalidEnumArgumentException()
            };
            var dp = new ECDomainParameters(c.Curve, c.G, c.N, c.H, c.GetSeed());
            var kp = new ECPublicKeyParameters("EC", c.Curve.DecodePoint(pubKey), dp);
            var l = Bip32Hash(chainCode, index, pubKey);

            while (true)
            {
                var ll = l.GetBytes(0, 32);
                var lr = l.GetBytes(32, 32);

                var parse256LL = new BigInteger(1, ll);
                var q = kp.Parameters.G.Multiply(parse256LL).Add(kp.Q);

                if (parse256LL.CompareTo(c.N) >= 0 || q.IsInfinity)
                {
                    l = Bip32Hash(chainCode, index, 1, lr);
                    continue;
                }
                
                return (q.Normalize().GetEncoded(true), lr);
            }
        }

        static byte[] Bip32Hash(byte[] chainCode, uint index, byte[] data)
        {
            using var hmacSha512 = new HMACSHA512(chainCode);
            return hmacSha512.ComputeHash(data.Concat(Ser32(index)));
        }

        static byte[] Bip32Hash(byte[] chainCode, uint index, byte prefix, byte[] data)
        {
            using var hmacSha512 = new HMACSHA512(chainCode);
            return hmacSha512.ComputeHash(Bytes.Concat([prefix], data, Ser32(index)));
        }

        private static byte[] Ser32(uint index) =>
        [
            (byte)((index >> 24) & 0xFF),
            (byte)((index >> 16) & 0xFF),
            (byte)((index >> 8) & 0xFF),
            (byte)((index >> 0) & 0xFF)
        ];
    }
}