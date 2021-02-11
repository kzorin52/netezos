﻿using System;
using System.Collections.Generic;
using System.Text.Json;
using Netezos.Encoding;

namespace Netezos.Contracts
{
    public sealed class ContractSchema : Schema, IFlat
    {
        public override PrimType Prim => PrimType.contract;

        public Schema Parameters { get; }

        public ContractSchema(MichelinePrim micheline) : base(micheline)
        {
            if (micheline.Args?.Count != 1 || !(micheline.Args[0] is MichelinePrim type))
                throw new FormatException($"Invalid {Prim} schema format");

            Parameters = Create(type);
        }

        internal override void WriteValue(Utf8JsonWriter writer, IMicheline value)
        {
            writer.WriteStringValue(Flatten(value));
        }

        public string Flatten(IMicheline value)
        {
            if (value is MichelineString micheString)
            {
                return micheString.Value;
            }
            else if (value is MichelineBytes micheBytes)
            {
                if (micheBytes.Value.Length < 22)
                    return Hex.Convert(micheBytes.Value);

                byte[] prefix;
                if (micheBytes.Value[0] == 0)
                {
                    if (micheBytes.Value[1] == 0)
                        prefix = Prefix.tz1;
                    else if (micheBytes.Value[1] == 1)
                        prefix = Prefix.tz2;
                    else if (micheBytes.Value[1] == 2)
                        prefix = Prefix.tz3;
                    else
                        return Hex.Convert(micheBytes.Value);
                }
                else if (micheBytes.Value[0] == 1)
                {
                    if (micheBytes.Value[21] == 0)
                        prefix = Prefix.KT1;
                    else
                        return Hex.Convert(micheBytes.Value);
                }
                else
                {
                    return Hex.Convert(micheBytes.Value);
                }

                var bytes = micheBytes.Value[0] == 0
                    ? micheBytes.Value.GetBytes(2, 20)
                    : micheBytes.Value.GetBytes(1, 20);

                var address = Base58.Convert(bytes, prefix);
                var entrypoint = micheBytes.Value.Length > 22
                    ? Utf8.Convert(micheBytes.Value.GetBytes(22, micheBytes.Value.Length - 22))
                    : string.Empty;

                return entrypoint.Length == 0 ? address : $"{address}%{entrypoint}";
            }
            else
            {
                throw FormatException(value);
            }
        }

        protected override List<IMicheline> GetArgs()
        {
            return new List<IMicheline>(1) { Parameters.ToMicheline() };
        }

        protected override IMicheline MapValue(object value)
        {
            switch (value)
            {
                case string str:
                    // TODO: validation & optimization
                    return new MichelineString(str);
                case byte[] bytes:
                    // TODO: validation
                    return new MichelineBytes(bytes);
                case JsonElement json when json.ValueKind == JsonValueKind.String:
                    // TODO: validation & optimization
                    return new MichelineString(json.GetString());
                default:
                    throw MapFailedException("invalid value");
            }
        }

        public override IMicheline Optimize(IMicheline value)
        {
            if (value is MichelineString micheStr)
            {
                var address = micheStr.Value.Substring(0, 36);
                var addressBytes = Base58.Parse(address, 3);
                var entrypointBytes = micheStr.Value.Length > 37
                    ? Utf8.Parse(micheStr.Value.Substring(37))
                    : null;

                var res = new byte[22 + (entrypointBytes?.Length ?? 0)];

                switch (address.Substring(0, 3))
                {
                    case "tz1":
                        addressBytes.CopyTo(res, 2);
                        res[0] = 0;
                        res[1] = 0;
                        break;
                    case "tz2":
                        addressBytes.CopyTo(res, 2);
                        res[0] = 0;
                        res[1] = 1;
                        break;
                    case "tz3":
                        addressBytes.CopyTo(res, 2);
                        res[0] = 0;
                        res[1] = 2;
                        break;
                    case "KT1":
                        addressBytes.CopyTo(res, 1);
                        res[0] = 1;
                        res[21] = 0;
                        break;
                    default:
                        throw FormatException(value);
                }

                if (entrypointBytes != null)
                    entrypointBytes.CopyTo(res, 22);

                return new MichelineBytes(res);
            }

            return value;
        }
    }
}
