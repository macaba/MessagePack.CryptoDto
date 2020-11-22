using NaCl.Core;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace MessagePack.CryptoDto.Managed
{
    public class CryptoDtoSerializer
    {
        private readonly object bufferLock = new object();

        private readonly byte[] headerLengthBytes = new byte[2];
        private readonly byte[] dtoNameLengthBytes = new byte[2];
        private readonly byte[] dtoLengthBytes = new byte[2];
        private readonly byte[] nonceBytes = new byte[Aead.NonceSize];
        private readonly byte[] tagBuffer = new byte[16];

        private readonly ArrayBufferWriter<byte> headerBuffer;
        private readonly ArrayBufferWriter<byte> dtoBuffer;
        private readonly ArrayBufferWriter<byte> aeBuffer;
        private readonly ArrayBufferWriter<byte> adBuffer;
        private readonly Memory<byte> cipherText;

        public CryptoDtoSerializer(int bufferSize = 1024, int msgPackBufferSize = 1024, int adBufferSize = 1024)
        {
            headerBuffer = new ArrayBufferWriter<byte>(msgPackBufferSize);
            dtoBuffer = new ArrayBufferWriter<byte>(msgPackBufferSize);
            aeBuffer = new ArrayBufferWriter<byte>(bufferSize);
            adBuffer = new ArrayBufferWriter<byte>(adBufferSize);
            cipherText = new byte[bufferSize];
        }

        public byte[] Serialize<T>(CryptoDtoChannelStore channelStore, string channelTag, CryptoDtoMode mode, T obj)
        {
            var channel = channelStore.GetChannel(channelTag);
            return Serialize(channel, mode, obj);
        }

        // Hint for callers using ArrayBufferWriter<byte> - output.WrittenSpan contains the serialised data
        public void Serialize<T>(IBufferWriter<byte> output, CryptoDtoChannelStore channelStore, string channelTag, CryptoDtoMode mode, T obj)
        {
            var channel = channelStore.GetChannel(channelTag);
            Serialize(output, channel, mode, obj);
        }

        public byte[] Serialize<T>(CryptoDtoChannel channel, CryptoDtoMode mode, T obj)
        {
            ArrayBufferWriter<byte> arrayBufferWriter = new ArrayBufferWriter<byte>();
            Serialize(arrayBufferWriter, channel, mode, obj);
            return arrayBufferWriter.WrittenSpan.ToArray();
        }

        // Hint for callers using ArrayBufferWriter<byte> - output.WrittenSpan contains the serialised data
        public void Serialize<T>(IBufferWriter<byte> output, CryptoDtoChannel channel, CryptoDtoMode mode, T dto)
        {
            lock (bufferLock)
            {
                ReadOnlySpan<byte> dtoNameBuffer = GetDtoNameBytes<T>();
                dtoBuffer.Clear();
                MessagePackSerializer.Serialize(dtoBuffer, dto);
                Pack(output, channel, mode, dtoNameBuffer, dtoBuffer.WrittenSpan);
            }
        }

        //[Obsolete]
        //public byte[] Pack(CryptoDtoChannelStore channelStore, string channelTag, CryptoDtoMode mode, ReadOnlySpan<byte> dtoNameBuffer, ReadOnlySpan<byte> dtoBuffer)
        //{
        //    var channel = channelStore.GetChannel(channelTag);
        //    return Pack(channel, mode, dtoNameBuffer, dtoBuffer);
        //}

        //[Obsolete]
        //public byte[] Pack(CryptoDtoChannel channel, CryptoDtoMode mode, ReadOnlySpan<byte> dtoNameBuffer, ReadOnlySpan<byte> dtoBuffer)
        //{
        //    ArrayBufferWriter<byte> arrayBufferWriter = new ArrayBufferWriter<byte>();
        //    Pack(arrayBufferWriter, channel, mode, dtoNameBuffer, dtoBuffer);
        //    return arrayBufferWriter.WrittenSpan.ToArray();
        //}

        public void Pack(IBufferWriter<byte> output, CryptoDtoChannel channel, CryptoDtoMode mode, ReadOnlySpan<byte> dtoNameBuffer, ReadOnlySpan<byte> dtoBuffer)
        {
            channel.GetTransmitKey(mode, out ulong sequenceToSend);
            CryptoDtoHeaderDto header = new CryptoDtoHeaderDto
            {
                ChannelTag = channel.ChannelTag,
                Mode = mode,
                Sequence = sequenceToSend
            };
            Pack(output, header, channel.TransmitChaCha20Poly1305, dtoNameBuffer, dtoBuffer);
        }

        //Can we change the ChaCha20Poly1305 input to some kind of ICrypto interface or action with 'Encrypt' and 'Decrypt'?
        private void Pack(IBufferWriter<byte> output, CryptoDtoHeaderDto header, ChaCha20Poly1305 crypto, ReadOnlySpan<byte> dtoNameBuffer, ReadOnlySpan<byte> dtoBuffer)
        {
            lock (bufferLock)
            {
                headerBuffer.Clear();
                MessagePackSerializer.Serialize(headerBuffer, header);
                ReadOnlySpan<byte> headerBytes = headerBuffer.WrittenSpan;

                ushort headerLength = (ushort)headerBytes.Length;
                BinaryPrimitives.WriteUInt16LittleEndian(headerLengthBytes, headerLength);
                ushort dtoNameLength = (ushort)dtoNameBuffer.Length;
                BinaryPrimitives.WriteUInt16LittleEndian(dtoNameLengthBytes, dtoNameLength);
                ushort dtoLength = (ushort)dtoBuffer.Length;
                BinaryPrimitives.WriteUInt16LittleEndian(dtoLengthBytes, dtoLength);

                switch (header.Mode)
                {
                    case CryptoDtoMode.ChaCha20Poly1305:
                        {
                            int adLength = 2 + headerLength;
                            int aeLength = 2 + dtoNameLength + 2 + dtoLength;

                            // Copy data into associated data buffer
                            adBuffer.Clear();
                            adBuffer.Write(headerLengthBytes);
                            adBuffer.Write(headerBytes);

                            // Copy data into authenticated encryption buffer
                            aeBuffer.Clear();
                            aeBuffer.Write(dtoNameLengthBytes);
                            aeBuffer.Write(dtoNameBuffer);
                            aeBuffer.Write(dtoLengthBytes);
                            aeBuffer.Write(dtoBuffer);

                            Span<byte> nonceSpan = new Span<byte>(nonceBytes);
                            BinaryPrimitives.WriteUInt64LittleEndian(nonceSpan.Slice(4), header.Sequence);

                            var adSpan = adBuffer.WrittenSpan;
                            var aeSpan = aeBuffer.WrittenSpan;
                            var cipherTextSpan = cipherText.Span.Slice(0, aeLength);
                            cipherTextSpan.Clear();
                            Span<byte> tagSpan = tagBuffer;
                            tagSpan.Clear();
                            crypto.Encrypt(nonceSpan, aeSpan, cipherTextSpan, tagSpan, adSpan);

                            output.Write(adSpan);
                            output.Write(cipherTextSpan);
                            output.Write(tagSpan);
                            break;
                        }
                    default:
                        throw new CryptographicException("Mode not recognised");
                }
            }
        }

        private Type CryptoDtoAttributeType = typeof(CryptoDtoAttribute);
        private ConcurrentDictionary<Type, byte[]> dtoNameCache = new ConcurrentDictionary<Type, byte[]>();
        private byte[] GetDtoNameBytes<T>()
        {
            var dtoType = typeof(T);
            if (!dtoNameCache.ContainsKey(dtoType))
            {
                if (Attribute.IsDefined(dtoType, CryptoDtoAttributeType))
                {
                    var shortDtoName = ((CryptoDtoAttribute)dtoType.GetCustomAttributes(CryptoDtoAttributeType, false)[0]).ShortDtoName;
                    dtoNameCache[dtoType] = Encoding.UTF8.GetBytes(shortDtoName);
                }
                else
                    dtoNameCache[dtoType] = Encoding.UTF8.GetBytes(dtoType.Name);
            }
            return dtoNameCache[dtoType];
        }
    }
}
