using System.Collections.Generic;
using System.Security.Cryptography;

namespace MessagePack.CryptoDto
{
    public class CryptoDtoChannelStore
    {
        readonly object channelStoreLock = new object();
        private readonly Dictionary<string, CryptoDtoChannel> channelStore;

        public CryptoDtoChannelStore()
        {
            channelStore = new Dictionary<string, CryptoDtoChannel>();
        }

        public int Count { get { lock (channelStoreLock) { return channelStore.Count; } } }

        /// <summary>
        /// Will throw CryptographicException if channel already exists
        /// </summary>
        /// <param name="channelTag"></param>
        /// <returns></returns>
        public void CreateChannel(string channelTag, int receiveSequenceHistorySize = 10)
        {
            lock (channelStoreLock)
            {
                if (channelStore.ContainsKey(channelTag))
                    throw new CryptographicException("Key tag already exists in store. (" + channelTag + ")");
                channelStore[channelTag] = new CryptoDtoChannel(channelTag, receiveSequenceHistorySize);
            }
        }

        public bool TryCreateChannel(string channelTag, int receiveSequenceHistorySize = 10)
        {
            lock (channelStoreLock)
            {
                if (channelStore.ContainsKey(channelTag))
                    return false;
                channelStore[channelTag] = new CryptoDtoChannel(channelTag, receiveSequenceHistorySize);
                return true;
            }
        }

        public bool TryCreateChannel(string channelTag, out CryptoDtoChannel channel, int receiveSequenceHistorySize = 10)
        {
            lock (channelStoreLock)
            {
                if (channelStore.ContainsKey(channelTag))
                {
                    channel = null;
                    return false;
                }
                channelStore[channelTag] = new CryptoDtoChannel(channelTag, receiveSequenceHistorySize);
                channel = channelStore[channelTag];
                return true;
            }
        }

        /// <summary>
        /// Will throw CryptographicException if channel does not exist
        /// </summary>
        /// <param name="channelTag"></param>
        /// <returns></returns>
        public CryptoDtoChannel GetChannel(string channelTag)
        {
            lock (channelStoreLock)
            {
                if (!channelStore.ContainsKey(channelTag))
                    throw new CryptographicException("Key tag does not exist in store. (" + channelTag + ")");
                return channelStore[channelTag];
            }
        }

        public bool TryGetChannel(string channelTag, out CryptoDtoChannel channel)
        {
            lock (channelStoreLock)
            {
                if (!channelStore.ContainsKey(channelTag))
                {
                    channel = null;
                    return false;
                }

                channel = channelStore[channelTag];
                return true;
            }
        }

        /// <summary>
        /// Will throw CryptographicException if channel does not exist
        /// </summary>
        /// <param name="channelTag"></param>
        public void DeleteChannel(string channelTag)
        {
            lock (channelStoreLock)
            {
                if (!channelStore.ContainsKey(channelTag))
                    throw new CryptographicException("Key tag does not exist in store. (" + channelTag + ")");
                channelStore.Remove(channelTag);
            }
        }

        public bool TryDeleteChannel(string channelTag)
        {
            lock (channelStoreLock)
            {
                if (!channelStore.ContainsKey(channelTag))
                    return false;

                channelStore.Remove(channelTag);
                return true;
            }
        }
    }
}
