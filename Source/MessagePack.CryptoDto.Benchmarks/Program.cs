using BenchmarkDotNet.Running;
using System;

namespace MessagePack.CryptoDto.Benchmarks
{
    class Program
    {
        static void Main(string[] args)
        {
            BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
            //BenchmarkRunner.Run<PackBenchmarks>();
            //BenchmarkRunner.Run<SerializeBenchmarks>();
            //BenchmarkRunner.Run<DeserializeBenchmarks>();
        }
    }
}
