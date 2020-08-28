using NaCl.Core;
using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace MessagePack.CryptoDto.Managed
{
    public static class CryptoDtoSerializer
    {
        public static byte[] Serialize<T>(CryptoDtoChannelStore channelStore, string channelTag, CryptoDtoMode mode, T obj)
        {
            var channel = channelStore.GetChannel(channelTag);
            var transmitKey = channel.GetTransmitKey(mode, out ulong sequenceToSend);
            return Serialise(channelTag, mode, transmitKey, sequenceToSend, obj);
        }

        public static byte[] Serialize<T>(CryptoDtoChannel channel, CryptoDtoMode mode, T obj)
        {
            var transmitKey = channel.GetTransmitKey(mode, out ulong sequenceToSend);
            return Serialise(channel.ChannelTag, mode, transmitKey, sequenceToSend, obj);
        }

        public static byte[] Pack(CryptoDtoChannelStore channelStore, string channelTag, CryptoDtoMode mode, byte[] dtoNameBuffer, byte[] dtoBuffer)
        {
            var channel = channelStore.GetChannel(channelTag);
            var transmitKey = channel.GetTransmitKey(mode, out ulong sequenceToSend);
            return Pack(channelTag, transmitKey, sequenceToSend, mode, dtoNameBuffer, dtoBuffer);
        }

        public static byte[] Pack(CryptoDtoChannel channel, CryptoDtoMode mode, byte[] dtoNameBuffer, byte[] dtoBuffer)
        {
            var transmitKey = channel.GetTransmitKey(mode, out ulong sequenceToSend);
            return Pack(channel.ChannelTag, transmitKey, sequenceToSend, mode, dtoNameBuffer, dtoBuffer);
        }

        private static byte[] Serialise<T>(string channelTag, CryptoDtoMode mode, ReadOnlySpan<byte> transmitKey, ulong sequenceToBeSent, T dto)
        {
            byte[] dtoNameBuffer = GetDtoNameBytes<T>();
            byte[] dtoBuffer = MessagePackSerializer.Serialize(dto);
            return Pack(channelTag, transmitKey, sequenceToBeSent, mode, dtoNameBuffer, dtoBuffer);
        }
        //Only change this to return ReadOnlySpan<byte> when UdpClient has a send method that accepts spans
        public static byte[] Pack(string channelTag, ReadOnlySpan<byte> transmitKey, ulong sequenceToBeSent, CryptoDtoMode mode, byte[] dtoNameBuffer, byte[] dtoBuffer)
        {
            CryptoDtoHeaderDto header = new CryptoDtoHeaderDto
            {
                ChannelTag = channelTag,
                Sequence = sequenceToBeSent,
                Mode = mode
            };

            var headerBuffer = MessagePackSerializer.Serialize(header);
            ushort headerLength = (ushort)headerBuffer.Length;
            ushort dtoNameLength = (ushort)dtoNameBuffer.Length;
            ushort dtoLength = (ushort)dtoBuffer.Length;

            switch (header.Mode)
            {
                case CryptoDtoMode.ChaCha20Poly1305:
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

                        Span<byte> nonceBuffer = stackalloc byte[Aead.NonceSize];
                        BinaryPrimitives.WriteUInt64LittleEndian(nonceBuffer.Slice(4), header.Sequence);

                        var aead = new ChaCha20Poly1305(transmitKey.ToArray());
                        byte[] aeadPayload = aead.Encrypt(aePayloadBuffer, adPayloadBuffer, nonceBuffer);
                        int aeadPayloadLength = aeadPayload.Length;

                        byte[] packetBuffer = new byte[2 + headerLength + aeadPayloadLength];

                        Array.Copy(BitConverter.GetBytes(headerLength), 0, packetBuffer, 0, 2);
                        Array.Copy(headerBuffer, 0, packetBuffer, 2, headerLength);
                        Array.Copy(aeadPayload, 0, packetBuffer, 2 + headerLength, aeadPayloadLength);
                        return packetBuffer;
                    }
                default:
                    throw new CryptographicException("Mode not recognised");
            }
        }

        //private static ConcurrentDictionary<Type, string> dtoNameStringCache = new ConcurrentDictionary<Type, string>();
        //private static string GetDtoName(Type dtoType)
        //{
        //    if (!dtoNameStringCache.ContainsKey(dtoType))
        //    {
        //        if (Attribute.IsDefined(dtoType, CryptoDtoAttributeType))
        //            dtoNameStringCache[dtoType] = ((CryptoDtoAttribute)dtoType.GetCustomAttributes(CryptoDtoAttributeType, false)[0]).ShortDtoName;
        //        else
        //            dtoNameStringCache[dtoType] = dtoType.Name;
        //    }
        //    return dtoNameStringCache[dtoType];
        //}

        private static Type CryptoDtoAttributeType = typeof(CryptoDtoAttribute);
        private static ConcurrentDictionary<Type, byte[]> dtoNameCache = new ConcurrentDictionary<Type, byte[]>();
        private static byte[] GetDtoNameBytes<T>()
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
