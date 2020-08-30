namespace MessagePack.CryptoDto
{
    [MessagePackObject]
    public struct CryptoDtoHeaderDto        //Changed this to struct - uses less memory on MessagePackSerializer.Deserialize. Only the ChannelTag gets heap memory allocated.
    {
        [Key(0)]
        public string ChannelTag { get; set; }
        [Key(1)]
        public ulong Sequence { get; set; }
        [Key(2)]
        public CryptoDtoMode Mode { get; set; }
    }
}
