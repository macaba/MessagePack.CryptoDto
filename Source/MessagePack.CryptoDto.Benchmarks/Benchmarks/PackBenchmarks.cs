using BenchmarkDotNet.Attributes;
using System;
using System.Buffers;
using System.IO;
using System.Text;

namespace MessagePack.CryptoDto.Benchmarks
{
    [MemoryDiagnoser]
    public class PackBenchmarks
    {
        private CryptoDtoChannelStore cryptoChannelStore;
        CryptoDtoSerializer serializer = new CryptoDtoSerializer();
        ArrayBufferWriter<byte> buffer = new ArrayBufferWriter<byte>(1024);
        private byte[] typeNameBytes;
        private byte[] dtoBytes;

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
            dtoBytes = ms.ToArray();
            typeNameBytes = Encoding.UTF8.GetBytes(nameof(BenchmarkDto));
        }


        [Benchmark]
        public void Pack_Allocate()
        {
            for (int i = 0; i < 10000; i++)
            {
                if (cryptoChannelStore.TryGetChannel("Benchmark", out CryptoDtoChannel channel))
                {
                    var packetBytes = serializer.Pack(channel, CryptoDtoMode.ChaCha20Poly1305, typeNameBytes, dtoBytes);
                }
            }
        }

        [Benchmark]
        public void Pack_ZeroAllocate()
        {
            for (int i = 0; i < 10000; i++)
            {
                if (cryptoChannelStore.TryGetChannel("Benchmark", out CryptoDtoChannel channel))
                {
                    buffer.Clear();
                    serializer.Pack(buffer, channel, CryptoDtoMode.ChaCha20Poly1305, typeNameBytes, dtoBytes);
                    var packetBytes = buffer.WrittenSpan;
                }
            }
        }
    }
}
