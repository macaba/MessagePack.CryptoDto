using NaCl.Core.Base;
using System;
using System.Linq;
using System.Security.Cryptography;

namespace MessagePack.CryptoDto
{
    public class CryptoDtoChannel
    {
        private readonly byte[] aeadTransmitKey;
        private uint transmitSequence;

        private readonly byte[] aeadReceiveKey;

        private uint[] receiveSequenceHistory;
        private int receiveSequenceHistoryDepth;
        private int receiveSequenceSizeMaxSize;

        private readonly byte[] hmacKey;

        public string ChannelTag { get; private set; }
        public DateTime LastTransmitUtc { get; private set; }
        public DateTime LastReceiveUtc { get; private set; }

        public CryptoDtoChannel(string channelTag, int receiveSequenceHistorySize = 10)
        {
            ChannelTag = channelTag;

            RNGCryptoServiceProvider rnd = new RNGCryptoServiceProvider();

            aeadReceiveKey = new byte[Snuffle.KEY_SIZE_IN_BYTES];
            rnd.GetBytes(aeadReceiveKey);

            aeadTransmitKey = new byte[Snuffle.KEY_SIZE_IN_BYTES];
            rnd.GetBytes(aeadTransmitKey);

            hmacKey = new byte[64];
            rnd.GetBytes(hmacKey);

            transmitSequence = 0;
            receiveSequenceSizeMaxSize = receiveSequenceHistorySize;
            if (receiveSequenceSizeMaxSize < 1)
                receiveSequenceSizeMaxSize = 1;
            receiveSequenceHistory = new uint[receiveSequenceSizeMaxSize];
            receiveSequenceHistoryDepth = 0;
        }

        public CryptoDtoChannel(CryptoDtoChannelConfigDto channelConfig, int receiveSequenceHistorySize = 10)
        {
            ChannelTag = channelConfig.ChannelTag;
            aeadReceiveKey = channelConfig.AeadReceiveKey;
            aeadTransmitKey = channelConfig.AeadTransmitKey;
            hmacKey = channelConfig.HmacKey;

            transmitSequence = 0;
            receiveSequenceSizeMaxSize = receiveSequenceHistorySize;
            if (receiveSequenceSizeMaxSize < 1)
                receiveSequenceSizeMaxSize = 1;
            receiveSequenceHistory = new uint[receiveSequenceSizeMaxSize];
            receiveSequenceHistoryDepth = 0;
        }

        public CryptoDtoChannelConfigDto GetRemoteEndpointChannelConfig()
        {
            return new CryptoDtoChannelConfigDto()
            {
                ChannelTag = string.Copy(ChannelTag),
                AeadReceiveKey = aeadTransmitKey.ToArray(),
                AeadTransmitKey = aeadReceiveKey.ToArray(),     //Swap the order for the remote endpoint
                HmacKey = hmacKey.ToArray()
            };
        }

        public byte[] GetReceiveKey(CryptoDtoMode mode)
        {
            switch (mode)
            {
                case CryptoDtoMode.AEAD_ChaCha20Poly1305:
                    return aeadReceiveKey;
                case CryptoDtoMode.HMAC_SHA256:
                    return hmacKey;
                default:
                    throw new CryptoDtoException("CryptoDtoMode value not handled.");
            }
        }

        public void CheckReceivedSequence(uint sequenceReceived)
        {
            if (Contains(sequenceReceived))
            {
                throw new CryptoDtoException("Received sequence has been duplicated.");         // Duplication or replay attack
            }

            if (receiveSequenceHistoryDepth < receiveSequenceSizeMaxSize)                       //If the buffer has been filled...
            {
                receiveSequenceHistory[receiveSequenceHistoryDepth++] = sequenceReceived;
            }
            else
            {
                var minValue = GetMin(out int minIndex);
                if (sequenceReceived < minValue)
                    throw new CryptoDtoException("Received sequence is too old.");              // Possible replay attack
                receiveSequenceHistory[minIndex] = sequenceReceived;
            }

            LastReceiveUtc = DateTime.UtcNow;
        }

        public byte[] GetTransmitKey(CryptoDtoMode mode, out uint sequenceToSend)
        {
            sequenceToSend = transmitSequence;
            transmitSequence++;
            LastTransmitUtc = DateTime.UtcNow;

            switch (mode)
            {
                case CryptoDtoMode.AEAD_ChaCha20Poly1305:
                    return aeadTransmitKey;
                case CryptoDtoMode.HMAC_SHA256:
                    return hmacKey;
                default:
                    throw new CryptoDtoException("CryptoDtoMode value not handled.");
            }
        }

        private bool Contains(uint sequence)
        {
            for (int i = 0; i < receiveSequenceHistoryDepth; i++)
            {
                if (receiveSequenceHistory[i] == sequence)
                    return true;
            }
            return false;
        }

        private uint GetMin(out int minIndex)
        {
            uint minValue = uint.MaxValue;
            minIndex = -1;
            int index = -1;

            for (int i = 0; i < receiveSequenceHistoryDepth; i++)
            {
                index++;

                if (receiveSequenceHistory[i] <= minValue)
                {
                    minValue = receiveSequenceHistory[i];
                    minIndex = index;
                }
            }
            return minValue;
        }
    }
}
