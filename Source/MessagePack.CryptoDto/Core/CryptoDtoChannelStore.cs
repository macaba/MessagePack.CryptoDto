using System;
using System.Collections.Generic;
using System.Linq;

namespace MessagePack.CryptoDto
{
    public class CryptoDtoChannelStore
    {
        readonly object channelStoreLock = new object();
        private Dictionary<string, CryptoDtoChannel> channelStore;

        public CryptoDtoChannelStore()
        {
            channelStore = new Dictionary<string, CryptoDtoChannel>();
        }

        public void AddChannel(string channelTag, byte[] transmitKey, byte[] receiveKey, int receiveSequenceHistorySize = 10)
        {
            lock (channelStoreLock)
            {
                if (channelStore.ContainsKey(channelTag))
                    throw new CryptoDtoException("Key tag already exists in store.");
                channelStore[channelTag] = new CryptoDtoChannel(channelTag, transmitKey, receiveKey, receiveSequenceHistorySize);
            }
        }

        public byte[] GetReceiveKey(string channelTag)
        {
            lock (channelStoreLock)
            {
                if (!channelStore.ContainsKey(channelTag))
                    throw new CryptoDtoException("Key tag does not exist in store.");

                return channelStore[channelTag].GetReceiveKey();
            }
        }

        public void CheckReceivedSequence(string channelTag, uint sequenceReceived)
        {
            lock (channelStoreLock)
            {
                if (!channelStore.ContainsKey(channelTag))
                    throw new CryptoDtoException("Key tag does not exist in store.");

                channelStore[channelTag].CheckReceivedSequence(sequenceReceived);
            }
        }

        public byte[] GetTransmitKey(string channelTag, out uint transmitSequence)
        {
            lock (channelStoreLock)
            {
                if (!channelStore.ContainsKey(channelTag))
                    throw new CryptoDtoException("Key tag does not exist in store.");

                return channelStore[channelTag].GetTransmitKey(out transmitSequence);
            }
        }

        public void DeleteChannel(string channelTag)
        {
            lock (channelStoreLock)
            {
                if (!channelStore.ContainsKey(channelTag))
                    throw new CryptoDtoException("Key tag does not exist in store.");
                channelStore.Remove(channelTag);
            }
        }

        public void DeleteChannelIfExists(string channelTag)
        {
            lock (channelStoreLock)
            {
                if (channelStore.ContainsKey(channelTag))
                    channelStore.Remove(channelTag);
            }
        }
    }
}
