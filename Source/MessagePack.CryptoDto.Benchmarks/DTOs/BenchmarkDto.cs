namespace MessagePack.CryptoDto.Benchmarks
{
    [MessagePackObject]
    public class BenchmarkDto
    {
        [Key(0)]
        public string Callsign { get; set; }
        [Key(1)]
        public uint SequenceCounter { get; set; }
        [Key(2)]
        public byte[] Audio { get; set; }
        [Key(3)]
        public bool LastPacket { get; set; }
    }
}
