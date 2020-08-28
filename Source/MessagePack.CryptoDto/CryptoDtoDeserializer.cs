using NaCl.Core;
using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace MessagePack.CryptoDto.Managed
{
    public static class CryptoDtoDeserializer
    {
        public static Deserializer Deserialize(CryptoDtoChannelStore channelStore, ReadOnlySpan<byte> bytes)
        {
            var header = Deserializer.GetHeader(bytes, out ushort headerLength);
            var channel = channelStore.GetChannel(header.ChannelTag);
            return new Deserializer(channel, headerLength, header, bytes, false);
        }

        public static Deserializer DeserializeIgnoreSequence(CryptoDtoChannelStore channelStore, ReadOnlySpan<byte> bytes)  //This is used for UDP channels where duplication is possible and the overhead of CryptographicException isn't acceptable. Use IsSequenceValid() in code to ignore the UDP packet.
        {
            var header = Deserializer.GetHeader(bytes, out ushort headerLength);
            var channel = channelStore.GetChannel(header.ChannelTag);
            return new Deserializer(channel, headerLength, header, bytes, true);
        }

        public static Deserializer Deserialize(CryptoDtoChannel channel, ReadOnlySpan<byte> bytes)
        {
            var header = Deserializer.GetHeader(bytes, out ushort headerLength);
            return new Deserializer(channel, headerLength, header, bytes, false);
        }

        public static Deserializer DeserializeIgnoreSequence(CryptoDtoChannel channel, ReadOnlySpan<byte> bytes)            //This is used for UDP channels where duplication is possible and the overhead of CryptographicException isn't acceptable. Use IsSequenceValid() in code to ignore the UDP packet.
        {
            var header = Deserializer.GetHeader(bytes, out ushort headerLength);
            return new Deserializer(channel, headerLength, header, bytes, true);
        }

        public ref struct Deserializer
        {
            private readonly CryptoDtoHeaderDto header;
            private readonly ReadOnlySpan<byte> dtoNameBuffer;
            private readonly ReadOnlySpan<byte> dataBuffer;
            private readonly bool sequenceValid;

            internal Deserializer(CryptoDtoChannel channel, ushort headerLength, CryptoDtoHeaderDto header, ReadOnlySpan<byte> bytes, bool ignoreSequence)
            {
                sequenceValid = false;
                this.header = header;

                if (header.ChannelTag != channel.ChannelTag)
                    throw new CryptographicException("Channel Tag doesn't match provided Channel");

                switch (header.Mode)
                {
                    case CryptoDtoMode.ChaCha20Poly1305:
                        {
                            int aeLength = bytes.Length - (2 + headerLength);
                            ReadOnlySpan<byte> aePayloadBuffer = bytes.Slice(2 + headerLength, aeLength);

                            ReadOnlySpan<byte> adBuffer = bytes.Slice(0, 2 + headerLength);

                            Span<byte> nonceBuffer = stackalloc byte[Aead.NonceSize];
                            BinaryPrimitives.WriteUInt64LittleEndian(nonceBuffer.Slice(4), header.Sequence);

                            ReadOnlySpan<byte> receiveKey = channel.GetReceiveKey(header.Mode);
                            var aead = new ChaCha20Poly1305(receiveKey.ToArray());
                            ReadOnlySpan<byte> decryptedPayload = aead.Decrypt(aePayloadBuffer.ToArray(), adBuffer.ToArray(), nonceBuffer);

                            if (ignoreSequence)
                                sequenceValid = channel.IsReceivedSequenceAllowed(header.Sequence);
                            else
                            {
                                channel.CheckReceivedSequence(header.Sequence);     //The packet has passed MAC, so now check if it's being duplicated or replayed
                                sequenceValid = true;
                            }

                            var dtoNameLength = Unsafe.ReadUnaligned<ushort>(ref MemoryMarshal.GetReference(decryptedPayload));    //.NET Standard 2.0 doesn't have BitConverter.ToUInt16(Span<T>)

                            if (decryptedPayload.Length < (2 + dtoNameLength))
                                throw new CryptographicException("Not enough bytes to process packet. (2) " + dtoNameLength + " " + decryptedPayload.Length);

                            dtoNameBuffer = decryptedPayload.Slice(2, dtoNameLength);

                            var dataLength = Unsafe.ReadUnaligned<ushort>(ref MemoryMarshal.GetReference(decryptedPayload.Slice(2 + dtoNameLength, 2)));    //.NET Standard 2.0 doesn't have BitConverter.ToUInt16(Span<T>)

                            if (decryptedPayload.Length < (2 + dtoNameLength + 2 + dataLength))
                                throw new CryptographicException("Not enough bytes to process packet. (3) " + dataLength + " " + decryptedPayload.Length);
                            dataBuffer = decryptedPayload.Slice(2 + dtoNameLength + 2, dataLength);
                            break;
                        }
                    default:
                        throw new CryptographicException("Mode not recognised");
                }
            }

            internal static CryptoDtoHeaderDto GetHeader(ReadOnlySpan<byte> bytes, out ushort headerLength)
            {
                headerLength = Unsafe.ReadUnaligned<ushort>(ref MemoryMarshal.GetReference(bytes));             //.NET Standard 2.0 doesn't have BitConverter.ToUInt16(Span<T>)               
                if (bytes.Length < (2 + headerLength))
                    throw new CryptographicException("Not enough bytes to process packet.");

                ReadOnlySpan<byte> headerDataBuffer = bytes.Slice(2, headerLength);
                return MessagePackSerializer.Deserialize<CryptoDtoHeaderDto>(headerDataBuffer.ToArray());
            }

            public string GetChannelTag()
            {
                return header.ChannelTag;
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
                return MessagePackSerializer.Deserialize<T>(dataBuffer.ToArray()); //When MessagePack has Span support, tweak this.
            }

            public byte[] GetDtoBytes()
            {
                return dataBuffer.ToArray();
            }

            public bool IsSequenceValid()           //Use this if the "Ignore Sequence" option was used for UDP channels
            {
                return sequenceValid;
            }
        }
    }
}
