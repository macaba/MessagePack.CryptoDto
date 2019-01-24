using System;

namespace MessagePack.CryptoDto
{
    public class CryptoDtoException : Exception
    {
        public CryptoDtoException(string message) : base(message) { }
    }
}
