﻿namespace Netezos.Micheline
{
    public enum PrimType : byte
    {
        parameter           = 0x00,
        storage             = 0x01,
        code                = 0x02,
        False               = 0x03,
        Elt                 = 0x04,
        Left                = 0x05,
        None                = 0x06,
        Pair                = 0x07,
        Right               = 0x08,
        Some                = 0x09,
        True                = 0x0A,
        Unit                = 0x0B,
        PACK                = 0x0C,
        UNPACK              = 0x0D,
        BLAKE2B             = 0x0E,
        SHA256              = 0x0F,
        SHA512              = 0x10,
        ABS                 = 0x11,
        ADD                 = 0x12,
        AMOUNT              = 0x13,
        AND                 = 0x14,
        BALANCE             = 0x15,
        CAR                 = 0x16,
        CDR                 = 0x17,
        CHECK_SIGNATURE     = 0x18,
        COMPARE             = 0x19,
        CONCAT              = 0x1A,
        CONS                = 0x1B,
        CREATE_ACCOUNT      = 0x1C,
        CREATE_CONTRACT     = 0x1D,
        IMPLICIT_ACCOUNT    = 0x1E,
        DIP                 = 0x1F,
        DROP                = 0x20,
        DUP                 = 0x21,
        EDIV                = 0x22,
        EMPTY_MAP           = 0x23,
        EMPTY_SET           = 0x24,
        EQ                  = 0x25,
        EXEC                = 0x26,
        FAILWITH            = 0x27,
        GE                  = 0x28,
        GET                 = 0x29,
        GT                  = 0x2A,
        HASH_KEY            = 0x2B,
        IF                  = 0x2C,
        IF_CONS             = 0x2D,
        IF_LEFT             = 0x2E,
        IF_NONE             = 0x2F,
        INT                 = 0x30,
        LAMBDA              = 0x31,
        LE                  = 0x32,
        LEFT                = 0x33,
        LOOP                = 0x34,
        LSL                 = 0x35,
        LSR                 = 0x36,
        LT                  = 0x37,
        MAP                 = 0x38,
        MEM                 = 0x39,
        MUL                 = 0x3A,
        NEG                 = 0x3B,
        NEQ                 = 0x3C,
        NIL                 = 0x3D,
        NONE                = 0x3E,
        NOT                 = 0x3F,
        NOW                 = 0x40,
        OR                  = 0x41,
        PAIR                = 0x42,
        PUSH                = 0x43,
        RIGHT               = 0x44,
        SIZE                = 0x45,
        SOME                = 0x46,
        SOURCE              = 0x47,
        SENDER              = 0x48,
        SELF                = 0x49,
        STEPS_TO_QUOTA      = 0x4A,
        SUB                 = 0x4B,
        SWAP                = 0x4C,
        TRANSFER_TOKENS     = 0x4D,
        SET_DELEGATE        = 0x4E,
        UNIT                = 0x4F,
        UPDATE              = 0x50,
        XOR                 = 0x51,
        ITER                = 0x52,
        LOOP_LEFT           = 0x53,
        ADDRESS             = 0x54,
        CONTRACT            = 0x55,
        ISNAT               = 0x56,
        CAST                = 0x57,
        RENAME              = 0x58,
        @bool               = 0x59,
        contract            = 0x5A,
        @int                = 0x5B,
        key                 = 0x5C,
        key_hash            = 0x5D,
        lambda              = 0x5E,
        list                = 0x5F,
        map                 = 0x60,
        big_map             = 0x61,
        nat                 = 0x62,
        option              = 0x63,
        or                  = 0x64,
        pair                = 0x65,
        set                 = 0x66,
        signature           = 0x67,
        @string             = 0x68,
        bytes               = 0x69,
        mutez               = 0x6A,
        timestamp           = 0x6B,
        unit                = 0x6C,
        operation           = 0x6D,
        address             = 0x6E,
        SLICE               = 0x6F,
        DIG                 = 0x70,
        DUG                 = 0x71,
        EMPTY_BIG_MAP       = 0x72,
        APPLY               = 0x73,
        chain_id            = 0x74,
        CHAIN_ID            = 0x75
    }
}
