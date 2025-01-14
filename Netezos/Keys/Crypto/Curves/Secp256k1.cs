﻿using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Netezos.Utils;
using Org.BouncyCastle.Asn1.X9;

namespace Netezos.Keys
{
    internal class Secp256k1 : Curve
    {
        #region static
        static readonly byte[] _Slip10Seed = { 66, 105, 116, 99, 111, 105, 110, 32, 115, 101, 101, 100 }; // "Bitcoin seed"
        #endregion
        
        public override ECKind Kind => ECKind.Secp256k1;

        public override byte[] AddressPrefix => Prefix.tz2;
        public override byte[] PublicKeyPrefix => Prefix.sppk;
        public override byte[] PrivateKeyPrefix => Prefix.spsk;
        public override byte[] SignaturePrefix => Prefix.spsig;
        public override byte[] Slip10Seed => _Slip10Seed;

        public override byte[] ExtractPrivateKey(byte[] bytes)
        {
            if (bytes.Length != 32)
                throw new ArgumentException("Invalid private key length. Expected 32 bytes.");

            return bytes.GetBytes(0, 32);
        }

        public override byte[] GeneratePrivateKey()
        {
            var res = new byte[32];

            do { RNG.WriteBytes(res); }
            while (new BigInteger(1, res).CompareTo(Curve.N) >= 0);

            return res;
        }

        public static readonly X9ECParameters Curve = SecNamedCurves.GetByName("secp256k1");
        private static readonly ECDomainParameters Params = new(Curve.Curve, Curve.G, Curve.N, Curve.H, Curve.GetSeed());

        public override byte[] GetPublicKey(byte[] privateKey)
        {
            var key = new ECPrivateKeyParameters(new BigInteger(1, privateKey), Params);
            return key.Parameters.G.Multiply(key.D).GetEncoded(true);
        }

        public override Signature Sign(byte[] msg, byte[] prvKey)
        {
            var privateKey = new ECPrivateKeyParameters(new BigInteger(1, prvKey), Params);
            var signer = new ECDsaSigner(new HMacDsaKCalculator(new Blake2bDigest(256)));

            signer.Init(true, privateKey);
            var rs = signer.GenerateSignature(Blake2b.GetDigest(msg));

            if (rs[1].CompareTo(Curve.N.Divide(BigInteger.Two)) > 0)
                rs[1] = Curve.N.Subtract(rs[1]);

            var r = rs[0].ToByteArrayUnsigned().Align(32);
            var s = rs[1].ToByteArrayUnsigned().Align(32);

            return new Signature(r.Concat(s), SignaturePrefix);
        }

        public override bool Verify(byte[] msg, byte[] sig, byte[] pubKey)
        {
            var digest = Blake2b.GetDigest(msg);
            var r = sig.GetBytes(0, 32);
            var s = sig.GetBytes(32, 32);

            var publicKey = new ECPublicKeyParameters(Curve.Curve.DecodePoint(pubKey), Params);
            var signer = new ECDsaSigner();

            signer.Init(false, publicKey);
            return signer.VerifySignature(digest, new BigInteger(1, r), new BigInteger(1, s));
        }
    }
}
