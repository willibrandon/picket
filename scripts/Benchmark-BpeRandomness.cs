#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PackAsTool=false
#:property ManagePackageVersionsCentrally=false
#:package BenchmarkDotNet@0.15.8
#:package Microsoft.Bcl.Memory@10.0.10
#:package Microsoft.ML.Tokenizers.Data.Cl100kBase@2.0.0
#:project ../src/Picket.Engine/Picket.Engine.csproj
#:include BpeRandomnessBenchmarks.cs

using BenchmarkDotNet.Running;

BenchmarkRunner.Run<BpeRandomnessBenchmarks>(args: args);
