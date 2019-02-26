using System;
using System.Collections.Generic;
using System.Text;

namespace MessagePack.CryptoDto
{
    public enum CryptoDtoMode
    {
        Undefined = 0,
        None = 1,
        HMAC_SHA256 = 2,
        AEAD_ChaCha20Poly1305 = 3
    }
}