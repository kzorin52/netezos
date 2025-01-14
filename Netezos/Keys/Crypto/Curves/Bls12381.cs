﻿using Org.BouncyCastle.Asn1.X9;

namespace Netezos.Keys
{
    class Bls12381 : Curve
    {
        public override ECKind Kind => ECKind.Bls12381;

        public override byte[] AddressPrefix => Prefix.tz4;
        public override byte[] PublicKeyPrefix => Prefix.BLpk;
        public override byte[] PrivateKeyPrefix => Prefix.BLsk;
        public override byte[] SignaturePrefix => Prefix.BLsig;
        public override byte[] Slip10Seed => throw new NotImplementedException("BLS12-381 curve is not implemented yet");

        public override byte[] ExtractPrivateKey(byte[] bytes)
        {
            throw new NotImplementedException("BLS12-381 curve is not implemented yet");
        }

        public override byte[] GeneratePrivateKey()
        {
            throw new NotImplementedException("BLS12-381 curve is not implemented yet");
        }

        public override byte[] GetPublicKey(byte[] privateKey)
        {
            throw new NotImplementedException("BLS12-381 curve is not implemented yet");
        }

        public override Signature Sign(byte[] msg, byte[] prvKey)
        {
            throw new NotImplementedException("BLS12-381 curve is not implemented yet");
        }

        public override bool Verify(byte[] msg, byte[] sig, byte[] pubKey)
        {
            throw new NotImplementedException("BLS12-381 curve is not implemented yet");
        }
    }
}
