using BenchmarkDotNet.Attributes;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MessagePack.CryptoDto.Benchmarks
{
    [MemoryDiagnoser]
    public class DeserializeBenchmarks
    {
        private CryptoDtoChannelStore cryptoChannelStore;
        ArrayBufferWriter<byte> buffer = new ArrayBufferWriter<byte>(1024);
        private CryptoDtoChannel remoteChannel;
        private byte[] cryptoDtoPacket;
        CryptoDtoSerializer serializer = new CryptoDtoSerializer();

        [GlobalSetup]
        public void Setup()
        {
            cryptoChannelStore = new CryptoDtoChannelStore();
            cryptoChannelStore.CreateChannel("Benchmark");
            var dto = new BenchmarkDto()
            {
                Callsign = "Benchmark",
                SequenceCounter = 0,
                Audio = new byte[200],
                LastPacket = false
            };
            Random rnd = new Random();
            rnd.NextBytes(dto.Audio);
            MemoryStream ms = new MemoryStream();
            MessagePackSerializer.Serialize(ms, dto);

            cryptoChannelStore.TryGetChannel("Benchmark", out var channel);
            var config = channel.GetRemoteEndpointChannelConfig();
            remoteChannel = new CryptoDtoChannel(config);

            cryptoDtoPacket = serializer.Serialize(cryptoChannelStore, "Benchmark", CryptoDtoMode.ChaCha20Poly1305, dto);
        }

        [Benchmark]
        public void Deserialize_Allocate()
        {
            for (int i = 0; i < 10000; i++)
            {
                var deserializer = CryptoDtoDeserializer.DeserializeIgnoreSequence(remoteChannel, cryptoDtoPacket);
            }
        }

        [Benchmark]
        public void Deserialize_LowAllocate()
        {
            for (int i = 0; i < 10000; i++)
            {
                buffer.Clear();
                var deserializer = CryptoDtoDeserializer.DeserializeIgnoreSequence(buffer, remoteChannel, cryptoDtoPacket);
            }
        }

        [Benchmark]
        public void DeserializeGetDto_Allocate()
        {
            for (int i = 0; i < 10000; i++)
            {
                var deserializer = CryptoDtoDeserializer.DeserializeIgnoreSequence(remoteChannel, cryptoDtoPacket);
                var dto = deserializer.GetDto<BenchmarkDto>();
            }
        }

        [Benchmark]
        public void DeserializeGetDto_LowAllocate()
        {
            for (int i = 0; i < 10000; i++)
            {
                buffer.Clear();
                var deserializer = CryptoDtoDeserializer.DeserializeIgnoreSequence(buffer, remoteChannel, cryptoDtoPacket);
                var dto = deserializer.GetDto<BenchmarkDto>();
            }
        }
    }
}
