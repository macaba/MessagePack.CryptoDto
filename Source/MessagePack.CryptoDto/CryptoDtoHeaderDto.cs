namespace MessagePack.CryptoDto
{
    [MessagePackObject]
    public class CryptoDtoHeaderDto
    {
        [Key(0)]
        public string ChannelTag { get; set; }
        [Key(1)]
        public ulong Sequence { get; set; }
        [Key(2)]
        public CryptoDtoMode Mode { get; set; }
    }
}
