using System;
using System.Collections.Generic;
using System.Text;

namespace MessagePack.CryptoDto
{
    public enum CryptoDtoMode
    {
        HMAC_SHA256 = 0,
        AEAD_ChaCha20Poly1305 = 1
    }
}
