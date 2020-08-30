using BenchmarkDotNet.Attributes;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MessagePack.CryptoDto.Benchmarks
{
    [MemoryDiagnoser]
    public class SerializeBenchmarks
    {
        private CryptoDtoChannelStore cryptoChannelStore;
        CryptoDtoSerializer serializer = new CryptoDtoSerializer();
        ArrayBufferWriter<byte> buffer = new ArrayBufferWriter<byte>(1024);
        private BenchmarkDto dto;

        [GlobalSetup]
        public void Setup()
        {
            cryptoChannelStore = new CryptoDtoChannelStore();
            cryptoChannelStore.CreateChannel("Benchmark");
            dto = new BenchmarkDto()
            {
                Callsign = "Benchmark",
                SequenceCounter = 0,
                Audio = new byte[200],
                LastPacket = false
            };
            Random rnd = new Random();
            rnd.NextBytes(dto.Audio);
        }

        [Benchmark]
        public void Serialize_Allocate()
        {
            for (int i = 0; i < 10000; i++)
            {
                if (cryptoChannelStore.TryGetChannel("Benchmark", out CryptoDtoChannel channel))
                {
                    var packetBytes = serializer.Serialize(channel, CryptoDtoMode.ChaCha20Poly1305, dto);
                }
            }
        }

        [Benchmark]
        public void Serialize_ZeroAllocate()
        {
            for (int i = 0; i < 10000; i++)
            {
                if (cryptoChannelStore.TryGetChannel("Benchmark", out CryptoDtoChannel channel))
                {
                    buffer.Clear();
                    serializer.Serialize(buffer, channel, CryptoDtoMode.ChaCha20Poly1305, dto);
                    var packetBytes = buffer.WrittenSpan;
                }
            }
        }
    }
}
