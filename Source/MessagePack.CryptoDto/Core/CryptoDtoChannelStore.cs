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

        public CryptoDtoChannel CreateChannel(string channelTag, int receiveSequenceHistorySize = 10)
        {
            lock (channelStoreLock)
            {
                if (channelStore.ContainsKey(channelTag))
                    throw new CryptoDtoException("Key tag already exists in store.");
                channelStore[channelTag] = new CryptoDtoChannel(channelTag, receiveSequenceHistorySize);
                return channelStore[channelTag];
            }
        }

        public byte[] GetReceiveKey(string channelTag, CryptoDtoMode mode)
        {
            lock (channelStoreLock)
            {
                if (!channelStore.ContainsKey(channelTag))
                    throw new CryptoDtoException("Key tag does not exist in store.");

                return channelStore[channelTag].GetReceiveKey(mode);
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

        public byte[] GetTransmitKey(string channelTag, CryptoDtoMode mode, out uint transmitSequence)
        {
            lock (channelStoreLock)
            {
                if (!channelStore.ContainsKey(channelTag))
                    throw new CryptoDtoException("Key tag does not exist in store.");

                return channelStore[channelTag].GetTransmitKey(mode, out transmitSequence);
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
