using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace MessagePack.CryptoDto
{
    public class CryptoDtoChannel
    {
        private readonly byte[] transmitKey;
        private uint transmitSequence;

        private readonly byte[] receiveKey;

        private uint[] receiveSequenceHistory;
        private int receiveSequenceHistoryDepth;
        private int receiveSequenceSizeMaxSize;

        public string ChannelTag { get; private set; }

        public CryptoDtoChannel(string channelTag, byte[] transmitKey, byte[] receiveKey, int receiveSequenceHistorySize = 10)
        {
            ChannelTag = channelTag;
            this.transmitKey = transmitKey;
            this.receiveKey = receiveKey;
            transmitSequence = 0;
            receiveSequenceSizeMaxSize = receiveSequenceHistorySize;
            if (receiveSequenceSizeMaxSize < 1)
                receiveSequenceSizeMaxSize = 1;
            receiveSequenceHistory = new uint[receiveSequenceSizeMaxSize];
            receiveSequenceHistoryDepth = 0;
        }

        public byte[] GetReceiveKey()
        {
            return receiveKey;
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
        }

        public byte[] GetTransmitKey(out uint sequenceToSend)
        {
            sequenceToSend = transmitSequence;
            transmitSequence++;
            return transmitKey;
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
