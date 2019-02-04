using NaCl.Core;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace MessagePack.CryptoDto
{
    public static class CryptoDtoSerializer
    {
        public static byte[] Serialize<T>(CryptoDtoChannelStore channelStore, string channelTag, CryptoDtoMode mode, T obj)
        {
            var transmitKey = channelStore.GetTransmitKey(channelTag, mode, out uint sequenceToSend);
            return Serialise(channelTag, mode, transmitKey, sequenceToSend, obj);
        }

        public static byte[] Serialize<T>(CryptoDtoChannel channel, CryptoDtoMode mode, T obj)
        {
            var transmitKey = channel.GetTransmitKey(mode, out uint sequenceToSend);
            return Serialise(channel.ChannelTag, mode, transmitKey, sequenceToSend, obj);
        }

        private static byte[] Serialise<T>(string channelTag, CryptoDtoMode mode, byte[] transmitKey, uint sequenceToBeSent, T dto)
        {
            CryptoDtoHeaderDto header = new CryptoDtoHeaderDto
            {
                ChannelTag = channelTag,
                Sequence = sequenceToBeSent,
                Mode = mode
            };

            var headerBuffer = MessagePackSerializer.Serialize(header);
            ushort headerLength = (ushort)headerBuffer.Length;

            byte[] dtoNameBuffer = GetDtoNameBytes<T>();
            ushort dtoNameLength = (ushort)dtoNameBuffer.Length;

            var dtoBuffer = MessagePackSerializer.Serialize(dto);
            ushort dtoLength = (ushort)dtoBuffer.Length;

            switch (header.Mode)
            {
                case CryptoDtoMode.HMAC_SHA256:
                    {
                        int macPayloadLength = 2 + headerLength + 2 + dtoNameLength + 2 + dtoLength;
                        var macPayloadBuffer = new byte[macPayloadLength];

                        Array.Copy(BitConverter.GetBytes(headerLength), 0, macPayloadBuffer, 0, 2);
                        Array.Copy(headerBuffer, 0, macPayloadBuffer, 2, headerLength);

                        Array.Copy(BitConverter.GetBytes(dtoNameLength), 0, macPayloadBuffer, 2 + headerLength, 2);
                        Array.Copy(dtoNameBuffer, 0, macPayloadBuffer, 2 + headerLength + 2, dtoNameLength);

                        Array.Copy(BitConverter.GetBytes(dtoLength), 0, macPayloadBuffer, 2 + headerLength + 2 + dtoNameLength, 2);
                        Array.Copy(dtoBuffer, 0, macPayloadBuffer, 2 + headerLength + 2 + dtoNameLength + 2, dtoLength);

                        using (HMACSHA256 hmac = new HMACSHA256(transmitKey))
                        {
                            var macBuffer = hmac.ComputeHash(macPayloadBuffer);

                            byte[] packetBuffer = new byte[macPayloadLength + macBuffer.Length];

                            Array.Copy(macPayloadBuffer, 0, packetBuffer, 0, macPayloadLength);
                            Array.Copy(macBuffer, 0, packetBuffer, macPayloadLength, macBuffer.Length);
                            return packetBuffer;
                        }
                    }
                case CryptoDtoMode.AEAD_ChaCha20Poly1305:
                    {

                        int aePayloadLength = 2 + dtoNameLength + 2 + dtoLength;
                        var aePayloadBuffer = new byte[aePayloadLength];

                        Array.Copy(BitConverter.GetBytes(dtoNameLength), 0, aePayloadBuffer, 0, 2);
                        Array.Copy(dtoNameBuffer, 0, aePayloadBuffer, 2, dtoNameLength);

                        Array.Copy(BitConverter.GetBytes(dtoLength), 0, aePayloadBuffer, 2 + dtoNameLength, 2);
                        Array.Copy(dtoBuffer, 0, aePayloadBuffer, 2 + dtoNameLength + 2, dtoLength);

                        int adPayloadLength = 2 + headerLength;
                        var adPayloadBuffer = new byte[adPayloadLength];

                        Array.Copy(BitConverter.GetBytes(headerLength), 0, adPayloadBuffer, 0, 2);
                        Array.Copy(headerBuffer, 0, adPayloadBuffer, 2, headerLength);

                        var nonceBuffer = new byte[12];
                        Array.Copy(BitConverter.GetBytes(header.Sequence), 0, nonceBuffer, 0, 4);

                        var aead = new ChaCha20Poly1305(transmitKey);
                        byte[] aeadPayload = aead.Encrypt(aePayloadBuffer, adPayloadBuffer, nonceBuffer);
                        int aeadPayloadLength = aeadPayload.Length;

                        byte[] packetBuffer = new byte[2 + headerLength + aeadPayloadLength];

                        Array.Copy(BitConverter.GetBytes(headerLength), 0, packetBuffer, 0, 2);
                        Array.Copy(headerBuffer, 0, packetBuffer, 2, headerLength);
                        Array.Copy(aeadPayload, 0, packetBuffer, 2 + headerLength, aeadPayloadLength);
                        return packetBuffer;
                    }
                default:
                    throw new CryptoDtoException("Mode not recognised");
            }
        }

        private static Dictionary<Type, string> dtoNameStringCache = new Dictionary<Type, string>();
        private static string GetDtoName(Type dtoType)
        {
            if (!dtoNameStringCache.ContainsKey(dtoType))
            {
                if (Attribute.IsDefined(dtoType, CryptoDtoAttributeType))
                    dtoNameStringCache[dtoType] = ((CryptoDtoAttribute)dtoType.GetCustomAttributes(CryptoDtoAttributeType, false)[0]).ShortDtoName;
                else
                    dtoNameStringCache[dtoType] = dtoType.Name;
            }
            return dtoNameStringCache[dtoType];
        }

        private static Type CryptoDtoAttributeType = typeof(CryptoDtoAttribute);
        private static Dictionary<Type, byte[]> dtoNameCache = new Dictionary<Type, byte[]>();
        private static byte[] GetDtoNameBytes<T>()
        {
            var dtoType = typeof(T);
            if (!dtoNameCache.ContainsKey(dtoType))
            {
                if (Attribute.IsDefined(dtoType, CryptoDtoAttributeType))
                    dtoNameCache[dtoType] = Encoding.UTF8.GetBytes(((CryptoDtoAttribute)dtoType.GetCustomAttributes(CryptoDtoAttributeType, false)[0]).ShortDtoName);
                else
                    dtoNameCache[dtoType] = Encoding.UTF8.GetBytes(dtoType.Name);
            }
            return dtoNameCache[dtoType];
        }

        private static Dictionary<string, byte[]> channelTagCache = new Dictionary<string, byte[]>();
        private static byte[] GetChannelTagBytes(string channelTag)
        {
            if (!channelTagCache.ContainsKey(channelTag))
                channelTagCache[channelTag] = Encoding.UTF8.GetBytes(channelTag);
            return channelTagCache[channelTag];
        }

        public static Deserializer Deserialize(CryptoDtoChannelStore channelStore, byte[] bytes)
        {
            return new Deserializer(channelStore, bytes);
        }

        public static Deserializer Deserialize(CryptoDtoChannel channel, byte[] bytes)
        {
            return new Deserializer(channel, bytes);
        }

        public ref struct Deserializer
        {
            readonly ushort headerLength;
            readonly CryptoDtoHeaderDto header;

            readonly int dtoNameLength;
            ReadOnlySpan<byte> dtoNameBuffer;

            readonly int dataLength;
            ReadOnlySpan<byte> dataBuffer;

            public Deserializer(CryptoDtoChannelStore channelStore, ReadOnlySpan<byte> bytes)
            {
                headerLength = Unsafe.ReadUnaligned<ushort>(ref MemoryMarshal.GetReference(bytes));                                 //.NET Standard 2.0 doesn't have BitConverter.ToUInt16(Span<T>)               
                ReadOnlySpan<byte> headerDataBuffer = bytes.Slice(2, headerLength);
                header = MessagePackSerializer.Deserialize<CryptoDtoHeaderDto>(headerDataBuffer.ToArray());

                switch (header.Mode)
                {
                    case CryptoDtoMode.HMAC_SHA256:
                        {
                            dtoNameLength = Unsafe.ReadUnaligned<ushort>(ref MemoryMarshal.GetReference(bytes.Slice(2 + headerLength, 2)));    //.NET Standard 2.0 doesn't have BitConverter.ToUInt16(Span<T>)
                            dtoNameBuffer = bytes.Slice(2 + headerLength + 2, dtoNameLength);

                            dataLength = Unsafe.ReadUnaligned<ushort>(ref MemoryMarshal.GetReference(bytes.Slice(2 + headerLength + 2 + dtoNameLength, 2)));    //.NET Standard 2.0 doesn't have BitConverter.ToUInt16(Span<T>)
                            dataBuffer = bytes.Slice(2 + headerLength + 2 + dtoNameLength + 2, dataLength);

                            int payloadLength = 2 + headerLength + 2 + dtoNameLength + 2 + dataLength;
                            ReadOnlySpan<byte> payloadBuffer = bytes.Slice(0, payloadLength);

                            ReadOnlySpan<byte> macBuffer = bytes.Slice(payloadLength, bytes.Length - payloadLength);
                            byte[] receiveKey = channelStore.GetReceiveKey(header.ChannelTag, header.Mode);

                            using (HMACSHA256 hmac = new HMACSHA256(receiveKey))
                            {
                                var hash = hmac.ComputeHash(payloadBuffer.ToArray());

                                if (!NaCl.Core.Internal.CryptoBytes.ConstantTimeEquals(hash, macBuffer.ToArray()))
                                    throw new CryptoDtoException("Packet failed hash test.");
                            }

                            channelStore.CheckReceivedSequence(header.ChannelTag, header.Sequence);     //The packet has passed MAC, so now check if it's being duplicated or replayed
                            break;
                        }
                    case CryptoDtoMode.AEAD_ChaCha20Poly1305:
                        {
                            int aeLength = bytes.Length - (2 + headerLength);
                            ReadOnlySpan<byte> aePayloadBuffer = bytes.Slice(2 + headerLength, aeLength);

                            ReadOnlySpan<byte> adBuffer = bytes.Slice(0, 2 + headerLength);

                            var nonceBuffer = new byte[12];
                            Array.Copy(BitConverter.GetBytes(header.Sequence), 0, nonceBuffer, 0, 4);

                            byte[] receiveKey = channelStore.GetReceiveKey(header.ChannelTag, header.Mode);
                            var aead = new ChaCha20Poly1305(receiveKey);
                            ReadOnlySpan<byte> decryptedPayload = aead.Decrypt(aePayloadBuffer.ToArray(), adBuffer.ToArray(), nonceBuffer);

                            channelStore.CheckReceivedSequence(header.ChannelTag, header.Sequence);     //The packet has passed MAC, so now check if it's being duplicated or replayed

                            dtoNameLength = Unsafe.ReadUnaligned<ushort>(ref MemoryMarshal.GetReference(decryptedPayload));    //.NET Standard 2.0 doesn't have BitConverter.ToUInt16(Span<T>)
                            dtoNameBuffer = decryptedPayload.Slice(2, dtoNameLength);

                            dataLength = Unsafe.ReadUnaligned<ushort>(ref MemoryMarshal.GetReference(decryptedPayload.Slice(2 + dtoNameLength, 2)));    //.NET Standard 2.0 doesn't have BitConverter.ToUInt16(Span<T>)
                            dataBuffer = decryptedPayload.Slice(2 + dtoNameLength + 2, dataLength);
                            break;
                        }
                    default:
                        throw new CryptoDtoException("Mode not recognised");
                }
            }

            public Deserializer(CryptoDtoChannel channel, ReadOnlySpan<byte> bytes)
            {
                headerLength = Unsafe.ReadUnaligned<ushort>(ref MemoryMarshal.GetReference(bytes));                                 //.NET Standard 2.0 doesn't have BitConverter.ToUInt16(Span<T>)
                ReadOnlySpan<byte> headerBuffer = bytes.Slice(2, headerLength);
                header = MessagePackSerializer.Deserialize<CryptoDtoHeaderDto>(headerBuffer.ToArray());

                if (header.ChannelTag != channel.ChannelTag)
                    throw new CryptoDtoException("Channel Tag doesn't match provided Channel");

                switch (header.Mode)
                {
                    case CryptoDtoMode.HMAC_SHA256:
                        {
                            dtoNameLength = Unsafe.ReadUnaligned<ushort>(ref MemoryMarshal.GetReference(bytes.Slice(2 + headerLength, 2)));    //.NET Standard 2.0 doesn't have BitConverter.ToUInt16(Span<T>)
                            dtoNameBuffer = bytes.Slice(2 + headerLength + 2, dtoNameLength);

                            dataLength = Unsafe.ReadUnaligned<ushort>(ref MemoryMarshal.GetReference(bytes.Slice(2 + headerLength + 2 + dtoNameLength, 2)));    //.NET Standard 2.0 doesn't have BitConverter.ToUInt16(Span<T>)
                            dataBuffer = bytes.Slice(2 + headerLength + 2 + dtoNameLength + 2, dataLength);

                            int payloadLength = 2 + headerLength + 2 + dtoNameLength + 2 + dataLength;
                            ReadOnlySpan<byte> payloadBuffer = bytes.Slice(0, payloadLength);

                            ReadOnlySpan<byte> macBuffer = bytes.Slice(payloadLength, bytes.Length - payloadLength);
                            byte[] receiveKey = channel.GetReceiveKey(header.Mode);

                            using (HMACSHA256 hmac = new HMACSHA256(receiveKey))
                            {
                                var hash = hmac.ComputeHash(payloadBuffer.ToArray());

                                if (!NaCl.Core.Internal.CryptoBytes.ConstantTimeEquals(hash, macBuffer.ToArray()))
                                    throw new CryptoDtoException("Packet failed hash test.");
                            }

                            channel.CheckReceivedSequence(header.Sequence);     //The packet has passed MAC, so now check if it's being duplicated or replayed
                            break;
                        }
                    case CryptoDtoMode.AEAD_ChaCha20Poly1305:
                        {
                            int aeLength = bytes.Length - (2 + headerLength);
                            ReadOnlySpan<byte> aePayloadBuffer = bytes.Slice(2 + headerLength, aeLength);

                            ReadOnlySpan<byte> adBuffer = bytes.Slice(0, 2 + headerLength);

                            var nonceBuffer = new byte[12];
                            Array.Copy(BitConverter.GetBytes(header.Sequence), 0, nonceBuffer, 0, 4);

                            byte[] receiveKey = channel.GetReceiveKey(header.Mode);
                            var aead = new ChaCha20Poly1305(receiveKey);
                            ReadOnlySpan<byte> decryptedPayload = aead.Decrypt(aePayloadBuffer.ToArray(), adBuffer.ToArray(), nonceBuffer);

                            channel.CheckReceivedSequence(header.Sequence);     //The packet has passed MAC, so now check if it's being duplicated or replayed

                            dtoNameLength = Unsafe.ReadUnaligned<ushort>(ref MemoryMarshal.GetReference(decryptedPayload));    //.NET Standard 2.0 doesn't have BitConverter.ToUInt16(Span<T>)
                            dtoNameBuffer = decryptedPayload.Slice(2, dtoNameLength);

                            dataLength = Unsafe.ReadUnaligned<ushort>(ref MemoryMarshal.GetReference(decryptedPayload.Slice(2 + dtoNameLength, 2)));    //.NET Standard 2.0 doesn't have BitConverter.ToUInt16(Span<T>)
                            dataBuffer = decryptedPayload.Slice(2 + dtoNameLength + 2, dataLength);
                            break;
                        }
                    default:
                        throw new CryptoDtoException("Mode not recognised");
                }
            }

            private void Stuff()
            {

            }

            public string GetChannelTag()
            {
                return header.ChannelTag;
            }

            public string GetDtoName()
            {
                return Encoding.UTF8.GetString(dtoNameBuffer.ToArray());              //This is fast, so unlikely to optimise without using unsafe or Span support?
            }

            public T GetDto<T>()
            {
                return MessagePackSerializer.Deserialize<T>(dataBuffer.ToArray()); //When MessagePack has Span support, tweak this.
            }
        }
    }
}
