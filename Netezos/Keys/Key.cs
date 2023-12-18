using Netezos.Encoding;

namespace Netezos.Keys
{
    public class Key
    {
        public string Address => PubKey.Address;
        public PubKey PubKey
        {
            get { return _PubKey ??= new PubKey(Curve.GetPublicKey(Data), Curve.Kind); }
        }
        PubKey? _PubKey;

        internal readonly Curve Curve;
        internal readonly byte[] Data;

        public Key(ECKind kind = ECKind.Ed25519)
        {
            Curve = Curve.FromKind(kind);
            Data = Curve.GeneratePrivateKey();
        }

        internal Key(byte[] bytes, ECKind kind)
        {
            Curve = Curve.FromKind(kind);
            Data = Curve.ExtractPrivateKey(bytes ?? throw new ArgumentNullException(nameof(bytes)));
        }

        public byte[] GetBytes()
        {
            return Data;
        }

        public string GetBase58()
        {
            return Base58.Convert(Data, Curve.PrivateKeyPrefix);
        }

        public string GetHex()
        {
            return Hex.Convert(Data);
        }

        public Signature Sign(byte[] bytes)
        {
            return Curve.Sign(bytes, Data);
        }

        public Signature Sign(string message)
        {
            return Curve.Sign(Utf8.Parse(message), Data);
        }

        /// <summary>
        /// Prepends forged operation bytes with 0x03 and signs the result
        /// </summary>
        /// <param name="bytes">Forged operation bytes</param>
        /// <returns></returns>
        public Signature SignOperation(byte[] bytes)
        {
            // bruh man... every call new array and allocation. Big brain?
            return Curve.Sign(ForSign.Concat(bytes), Data);
        }
        private static readonly byte[] ForSign = [0x3];

        public bool Verify(byte[] data, byte[] signature) => PubKey.Verify(data, signature);

        public bool Verify(string message, string signature) => PubKey.Verify(message, signature);

        public override string ToString() => GetBase58();

        #region static
        public static Key FromBytes(byte[] bytes, ECKind kind = ECKind.Ed25519)
            => new(bytes, kind);

        public static Key FromHex(string hex, ECKind kind = ECKind.Ed25519)
            => new(Hex.Parse(hex), kind);

        public static Key FromBase64(string base64, ECKind kind = ECKind.Ed25519)
            => new(Base64.Parse(base64), kind);

        public static Key FromBase58(string base58)
        {
            if (base58 == null)
                throw new ArgumentNullException(nameof(base58));

            if (base58.Length != 54 && base58.Length != 98)
                throw new ArgumentException("Invalid private key format. Expected base58 string of 54 or 98 characters.");

            var curve = Curve.FromPrivateKeyBase58(base58);
            var bytes = Base58.Parse(base58, curve.PrivateKeyPrefix);

            return new(bytes, curve.Kind);
        }

        public static Key FromMnemonic(Mnemonic mnemonic)
        {
            var seed = mnemonic.GetSeed();
            var key = new Key(seed.GetBytes(0, 32), ECKind.Ed25519);
            return key;
        }

        public static Key FromMnemonic(Mnemonic mnemonic, string email, string password)
        {
            var seed = mnemonic.GetSeed($"{email}{password}");
            var key = new Key(seed.GetBytes(0, 32), ECKind.Ed25519);
            return key;
        }

        public static Key FromMnemonic(Mnemonic mnemonic, string passphrase, ECKind kind = ECKind.Ed25519)
        {
            var seed = mnemonic.GetSeed(passphrase);
            var key = new Key(seed.GetBytes(0, 32), kind);
            return key;
        }
        #endregion
    }
}
