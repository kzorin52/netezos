﻿namespace Netezos;

internal static class BytesExtension
{
    public static byte[] Align(this byte[] src, int length)
    {
        if (src.Length >= length) return src;
        var res = new byte[length];
        Buffer.BlockCopy(src, 0, res, length - src.Length, src.Length);
        return res;
    }

    public static byte[] Concat(this byte[] src, byte[] data)
    {
        var res = new byte[src.Length + data.Length];
        Buffer.BlockCopy(src, 0, res, 0, src.Length);
        Buffer.BlockCopy(data, 0, res, src.Length, data.Length);
        return res;
    }

    public static byte[] Concat(this byte[] src, byte[] data, int count)
    {
        var res = new byte[src.Length + count];
        Buffer.BlockCopy(src, 0, res, 0, src.Length);
        Buffer.BlockCopy(data, 0, res, src.Length, count);
        return res;
    }

    public static void CopyTo(this byte[] src, byte[] dst, int dstOffset)
    {
        Buffer.BlockCopy(src, 0, dst, dstOffset, src.Length);
    }

    public static byte[] Copy(this byte[] src)
    {
        var res = new byte[src.Length];
        Buffer.BlockCopy(src, 0, res, 0, src.Length);
        return res;
    }

    public static byte[] Reverse(this byte[] data)
    {
        var res = new byte[data.Length];

        for (var i = 0; i < data.Length; i++)
            res[i] = data[data.Length - 1 - i];

        return res;
    }

    public static byte[] GetBytes(this byte[] src, int start, int length)
    {
        var res = new byte[length];
        Buffer.BlockCopy(src, start, res, 0, length);
        return res;
    }

    public static bool IsEqual(this byte[] src, byte[] data)
    {
        if (src.Length != data.Length)
            return false;

        return !src.Where((t, i) => t != data[i]).Any();
    }

    public static bool IsEqual(this byte[] src, int srcOffset, byte[] data)
    {
        if (src.Length - srcOffset != data.Length)
            return false;

        for (int i = srcOffset, j = 0; i < src.Length; i++, j++)
            if (src[i] != data[j])
                return false;

        return true;
    }

    public static bool StartWith(this byte[] src, byte[] data)
    {
        if (src.Length < data.Length)
            return false;

        return !data.Where((t, i) => src[i] != t).Any();
    }
}