﻿using System;
using System.Collections;
using System.Collections.Generic;
using System.Text.Json;
using Netezos.Encoding;

namespace Netezos.Contracts
{
    public sealed class BigMapSchema : Schema
    {
        public override PrimType Prim => PrimType.big_map;

        public override string Name => (Field ?? Type
            ?? Value.Field ?? Value.Type
            ?? Prim.ToString())
            + Suffix;

        public override string Signature =>
            $"{(Key is IFlat ? "big_map_flat" : "big_map")}:{Key.Signature}:{Value.Signature}";

        public Schema Key { get; }
        public Schema Value { get; }

        public BigMapSchema(MichelinePrim micheline) : base(micheline)
        {
            if (micheline.Args?.Count != 2
                || !(micheline.Args[0] is MichelinePrim key)
                || !(micheline.Args[1] is MichelinePrim value))
                throw new FormatException($"Invalid {Prim} schema format");

            Key = Create(key);
            Value = Create(value);
        }

        internal override void WriteValue(Utf8JsonWriter writer)
        {
            if (Key is IFlat)
            {
                writer.WriteStartObject();
                writer.WritePropertyName(Key.Prim.ToString());
                Value.WriteValue(writer);
                writer.WriteEndObject();
            }
            else
            {
                writer.WriteStartArray();
                writer.WriteStartObject();
                writer.WritePropertyName("key");
                Key.WriteValue(writer);
                writer.WritePropertyName("value");
                Value.WriteValue(writer);
                writer.WriteEndObject();
                writer.WriteEndArray();
            }
        }

        internal override void WriteValue(Utf8JsonWriter writer, IMicheline value)
        {
            if (value is MichelineInt micheInt)
            {
                writer.WriteStringValue(micheInt.Value.ToString());
            }
            else if (value is MichelineArray micheArray)
            {
                if (Key is IFlat key)
                    WriteMap(writer, key, micheArray);
                else
                    WriteKeyValues(writer, micheArray);
            }
            else
            {
                throw FormatException(value);
            }
        }

        void WriteMap(Utf8JsonWriter writer, IFlat key, MichelineArray items)
        {
            writer.WriteStartObject();

            foreach (var item in items)
            {
                if (!(item is MichelinePrim elt) || elt.Prim != PrimType.Elt || elt.Args?.Count != 2)
                    throw new FormatException($"Invalid big_map item {(item as MichelinePrim)?.Prim.ToString() ?? item.Type.ToString()}");

                writer.WritePropertyName(key.Flatten(elt.Args[0]));
                Value.WriteValue(writer, elt.Args[1]);
            }

            writer.WriteEndObject();
        }

        void WriteKeyValues(Utf8JsonWriter writer, MichelineArray items)
        {
            writer.WriteStartArray();

            foreach (var item in items)
            {
                writer.WriteStartObject();

                if (!(item is MichelinePrim elt) || elt.Prim != PrimType.Elt || elt.Args?.Count != 2)
                    throw new FormatException($"Invalid big_map item {(item as MichelinePrim)?.Prim.ToString() ?? item.Type.ToString()}");

                writer.WritePropertyName("key");
                Key.WriteValue(writer, elt.Args[0]);

                writer.WritePropertyName("value");
                Value.WriteValue(writer, elt.Args[1]);

                writer.WriteEndObject();
            }

            writer.WriteEndArray();
        }

        protected override List<IMicheline> GetArgs()
        {
            return new List<IMicheline>(2) { Key.ToMicheline(), Value.ToMicheline() };
        }

        protected override IMicheline MapValue(object value)
        {
            switch (value)
            {
                case IEnumerable e:
                    var arr1 = new MichelineArray();
                    foreach (var item in e)
                    {
                        var type = item.GetType();
                        var keyProp = type.GetProperty("Key") ?? type.GetProperty("key")
                            ?? throw MapFailedException("missed 'key' property");
                        var valueProp = type.GetProperty("Value") ?? type.GetProperty("value")
                            ?? throw MapFailedException("missed 'value' property");

                        arr1.Add(new MichelinePrim
                        {
                            Prim = PrimType.Elt,
                            Args = new List<IMicheline>(2)
                            {
                                Key.MapObject(keyProp.GetValue(item), true),
                                Value.MapObject(valueProp.GetValue(item), true)
                            }
                        });
                    }
                    return arr1;

                case JsonElement json when json.ValueKind == JsonValueKind.Object:
                    var arr2 = new MichelineArray();
                    foreach (var item in json.EnumerateObject())
                    {
                        arr2.Add(new MichelinePrim
                        {
                            Prim = PrimType.Elt,
                            Args = new List<IMicheline>(2)
                            {
                                Key.MapObject(item.Name, true),
                                Value.MapObject(item.Value, true)
                            }
                        });
                    }
                    return arr2;

                case JsonElement json when json.ValueKind == JsonValueKind.Array:
                    var arr3 = new MichelineArray();
                    foreach (var item in json.EnumerateArray())
                    {
                        if (!item.TryGetProperty("key", out var key) && !item.TryGetProperty("Key", out key))
                            throw MapFailedException("missed 'key' property");
                        if (!item.TryGetProperty("value", out var val) && !item.TryGetProperty("Value", out val))
                            throw MapFailedException("missed 'value' property");

                        arr3.Add(new MichelinePrim
                        {
                            Prim = PrimType.Elt,
                            Args = new List<IMicheline>(2)
                            {
                                Key.MapObject(key, true),
                                Value.MapObject(val, true)
                            }
                        });
                    }
                    return arr3;

                default:
                    throw MapFailedException("invalid value");
            }
        }

        public override IMicheline Optimize(IMicheline value)
        {
            if (value is MichelineArray micheArray)
            {
                foreach (var item in micheArray)
                {
                    var elt = item as MichelinePrim;
                    elt.Args[0] = Key.Optimize(elt.Args[0]);
                    elt.Args[1] = Value.Optimize(elt.Args[1]);
                }
            }

            return value;
        }
    }
}
