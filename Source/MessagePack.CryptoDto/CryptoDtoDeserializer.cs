using Microsoft.Toolkit.HighPerformance.Buffers;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace MessagePack.CryptoDto
{
    public static class CryptoDtoDeserializer
    {
        #region CryptoDtoChannelStore methods
        public static Deserializer Deserialize(CryptoDtoChannelStore channelStore, ReadOnlyMemory<byte> bytes)
        {
            var plaintextBuffer = new ArrayBufferWriter<byte>();
            return Deserialise(plaintextBuffer, channelStore, bytes);
        }

        public static Deserializer Deserialise(IBufferWriter<byte> plaintextBuffer, CryptoDtoChannelStore channelStore, ReadOnlyMemory<byte> bytes)
        {
            var header = Deserializer.GetHeader(bytes, out ushort headerLength);
            var channel = channelStore.GetChannel(header.ChannelTag);
            return new Deserializer(channel, headerLength, header, bytes.Span, false, plaintextBuffer);
        }

        public static Deserializer DeserializeIgnoreSequence(CryptoDtoChannelStore channelStore, ReadOnlyMemory<byte> bytes)  //This is used for UDP channels where duplication is possible and the overhead of CryptographicException isn't acceptable. Use IsSequenceValid() in code to ignore the UDP packet.
        {
            var plaintextBuffer = new ArrayBufferWriter<byte>();
            return DeserializeIgnoreSequence(plaintextBuffer, channelStore, bytes);
        }

        public static Deserializer DeserializeIgnoreSequence(IBufferWriter<byte> plaintextBuffer, CryptoDtoChannelStore channelStore, ReadOnlyMemory<byte> bytes)  //This is used for UDP channels where duplication is possible and the overhead of CryptographicException isn't acceptable. Use IsSequenceValid() in code to ignore the UDP packet.
        {
            var header = Deserializer.GetHeader(bytes, out ushort headerLength);
            var channel = channelStore.GetChannel(header.ChannelTag);
            return new Deserializer(channel, headerLength, header, bytes.Span, true, plaintextBuffer);
        }
        #endregion

        #region CryptoDtoChannel methods
        public static Deserializer Deserialize(CryptoDtoChannel channel, ReadOnlyMemory<byte> bytes)
        {
            var plaintextBuffer = new ArrayBufferWriter<byte>();
            return Deserialize(plaintextBuffer, channel, bytes);
        }

        public static Deserializer Deserialize(IBufferWriter<byte> plaintextBuffer, CryptoDtoChannel channel, ReadOnlyMemory<byte> bytes)
        {
            var header = Deserializer.GetHeader(bytes, out ushort headerLength);
            if (header.ChannelTag != channel.ChannelTag)
                throw new CryptographicException("Channel Tag doesn't match provided Channel");
            return new Deserializer(channel, headerLength, header, bytes.Span, false, plaintextBuffer);
        }

        public static Deserializer DeserializeIgnoreSequence(CryptoDtoChannel channel, ReadOnlyMemory<byte> bytes)            //This is used for UDP channels where duplication is possible and the overhead of CryptographicException isn't acceptable. Use IsSequenceValid() in code to ignore the UDP packet.
        {
            var plaintextBuffer = new ArrayBufferWriter<byte>();
            return DeserializeIgnoreSequence(plaintextBuffer, channel, bytes);
        }

        public static Deserializer DeserializeIgnoreSequence(IBufferWriter<byte> plaintextBuffer, CryptoDtoChannel channel, ReadOnlyMemory<byte> bytes)            //This is used for UDP channels where duplication is possible and the overhead of CryptographicException isn't acceptable. Use IsSequenceValid() in code to ignore the UDP packet.
        {
            var header = Deserializer.GetHeader(bytes, out ushort headerLength);
            if (header.ChannelTag != channel.ChannelTag)
                throw new CryptographicException("Channel Tag doesn't match provided Channel");
            return new Deserializer(channel, headerLength, header, bytes.Span, true, plaintextBuffer);
        }
        #endregion

        public ref struct Deserializer
        {
            private readonly string channelTag;
            private readonly ReadOnlySpan<byte> dtoNameBuffer;
            private readonly ReadOnlyMemory<byte> dtoBuffer;
            private readonly bool sequenceValid;

            internal Deserializer(CryptoDtoChannel channel, ushort headerLength, CryptoDtoHeaderDto header, ReadOnlySpan<byte> bytes, bool ignoreSequence, IBufferWriter<byte> plaintextBuffer)
            {
                sequenceValid = false;
                channelTag = header.ChannelTag;

                switch (header.Mode)
                {
                    case CryptoDtoMode.ChaCha20Poly1305:
                        {
                            int adLength = 2 + headerLength;
                            int aeLength = bytes.Length - adLength - 16;
                            ReadOnlySpan<byte> ad = bytes.Slice(0, adLength);
                            ReadOnlySpan<byte> ae = bytes.Slice(adLength, aeLength);
                            ReadOnlySpan<byte> tag = bytes.Slice(adLength + aeLength, 16);

                            Span<byte> nonce = stackalloc byte[Aead.NonceSize];
                            BinaryPrimitives.WriteUInt64LittleEndian(nonce.Slice(4), header.Sequence);

                            var aead = channel.ReceiveChaCha20Poly1305;

                            Memory<byte> plaintext = plaintextBuffer.GetMemory(aeLength).Slice(0, aeLength);
                            aead.Decrypt(nonce, ae, tag, plaintext.Span, ad);

                            if (ignoreSequence)
                                sequenceValid = channel.IsReceivedSequenceAllowed(header.Sequence);
                            else
                            {
                                channel.CheckReceivedSequence(header.Sequence);     //The packet has passed MAC, so now check if it's being duplicated or replayed
                                sequenceValid = true;
                            }

                            var dtoNameLength = Unsafe.ReadUnaligned<ushort>(ref MemoryMarshal.GetReference(plaintext.Span));    //.NET Standard 2.0 doesn't have BitConverter.ToUInt16(Span<T>)

                            if (plaintext.Length < (2 + dtoNameLength))
                                throw new CryptographicException("Not enough bytes to process packet. (2) " + dtoNameLength + " " + plaintext.Length);

                            dtoNameBuffer = plaintext.Span.Slice(2, dtoNameLength);

                            var dtoLength = Unsafe.ReadUnaligned<ushort>(ref MemoryMarshal.GetReference(plaintext.Span.Slice(2 + dtoNameLength, 2)));    //.NET Standard 2.0 doesn't have BitConverter.ToUInt16(Span<T>)

                            if (plaintext.Length < (2 + dtoNameLength + 2 + dtoLength))
                                throw new CryptographicException("Not enough bytes to process packet. (3) " + dtoLength + " " + plaintext.Length);
                            dtoBuffer = plaintext.Slice(2 + dtoNameLength + 2, dtoLength);
                            break;
                        }
                    default:
                        throw new CryptographicException("Mode not recognised");
                }
            }

            internal static CryptoDtoHeaderDto GetHeader(ReadOnlyMemory<byte> bytes, out ushort headerLength)
            {
                headerLength = Unsafe.ReadUnaligned<ushort>(ref MemoryMarshal.GetReference(bytes.Span));             //.NET Standard 2.0 doesn't have BitConverter.ToUInt16(Span<T>)               
                if (bytes.Length < (2 + headerLength))
                    throw new CryptographicException("Not enough bytes to process packet.");

                var headerDataBuffer = bytes.Slice(2, headerLength);
                return MessagePackSerializer.Deserialize<CryptoDtoHeaderDto>(headerDataBuffer);     //This allocates heap memory for the string. The struct itself is on the stack. Wait for https://github.com/neuecc/MessagePack-CSharp/issues/107
            }

            public string GetChannelTag()
            {
                return channelTag;
            }

            public string GetDtoName()
            {
                return Encoding.UTF8.GetString(dtoNameBuffer.ToArray());              //This is fast, so unlikely to optimise without using unsafe or Span support?
            }

            public byte[] GetDtoNameBytes()
            {
                return dtoNameBuffer.ToArray();
            }

            public T GetDto<T>()
            {
                return MessagePackSerializer.Deserialize<T>(dtoBuffer);
            }

            public byte[] GetDtoBytes()
            {
                return dtoBuffer.ToArray();
            }

            public MemoryOwner<byte> GetDtoMemory()
            {
                var memory = MemoryOwner<byte>.Allocate(dtoBuffer.Length);
                dtoBuffer.Span.CopyTo(memory.Span);
                return memory;
            }

            public bool IsSequenceValid()           //Use this if the "Ignore Sequence" option was used for UDP channels
            {
                return sequenceValid;
            }
        }
    }
}
