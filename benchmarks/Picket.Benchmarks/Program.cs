using BenchmarkDotNet.Running;
using Picket.Benchmarks;

BenchmarkSwitcher.FromAssembly(typeof(SecretScanBenchmarks).Assembly).Run(args);
