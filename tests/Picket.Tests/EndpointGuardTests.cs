using Picket.Security;
using System.Net;

namespace Picket.Tests;

/// <summary>
/// Tests outbound endpoint safety checks.
/// </summary>
[TestClass]
public sealed class EndpointGuardTests
{
    /// <summary>
    /// Gets or sets the current test context.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that public HTTPS provider endpoints are allowed.
    /// </summary>
    [TestMethod]
    public void EvaluateAllowsPublicHttpsEndpoint()
    {
        EndpointGuardResult result = EndpointGuard.Evaluate(
            new Uri("https://api.github.com/user"),
            [IPAddress.Parse("140.82.112.6")]);

        Assert.IsTrue(result.IsAllowed);
        Assert.AreEqual(EndpointGuardBlockReason.None, result.BlockReason);
    }

    /// <summary>
    /// Verifies that non-HTTPS provider endpoints are blocked by default.
    /// </summary>
    [TestMethod]
    public void EvaluateBlocksNonHttpsEndpointByDefault()
    {
        EndpointGuardResult result = EndpointGuard.Evaluate(
            new Uri("http://api.github.com/user"),
            [IPAddress.Parse("140.82.112.6")]);

        Assert.IsFalse(result.IsAllowed);
        Assert.AreEqual(EndpointGuardBlockReason.NonHttpsScheme, result.BlockReason);
    }

    /// <summary>
    /// Verifies that metadata service host names are blocked before DNS resolution.
    /// </summary>
    [TestMethod]
    public void EvaluateBlocksMetadataHosts()
    {
        EndpointGuardResult result = EndpointGuard.Evaluate(
            new Uri("https://metadata.google.internal./computeMetadata/v1/"),
            [IPAddress.Parse("8.8.8.8")]);

        Assert.IsFalse(result.IsAllowed);
        Assert.AreEqual(EndpointGuardBlockReason.MetadataHost, result.BlockReason);
    }

    /// <summary>
    /// Verifies that loopback, private, link-local, and reserved endpoint addresses are blocked.
    /// </summary>
    [TestMethod]
    public void EvaluateBlocksNonPublicAddresses()
    {
        IPAddress[] blockedAddresses =
        [
            IPAddress.Parse("127.0.0.1"),
            IPAddress.Parse("10.0.0.10"),
            IPAddress.Parse("172.16.0.1"),
            IPAddress.Parse("192.168.1.1"),
            IPAddress.Parse("169.254.169.254"),
            IPAddress.Parse("100.64.0.1"),
            IPAddress.Parse("198.18.0.1"),
            IPAddress.Parse("::1"),
            IPAddress.Parse("fe80::1"),
            IPAddress.Parse("fc00::1"),
            IPAddress.Parse("fec0::1"),
            IPAddress.Parse("2001:db8::1"),
            IPAddress.Parse("::127.0.0.1"),
            IPAddress.Parse("::10.0.0.1"),
            IPAddress.Parse("::ffff:169.254.169.254"),
            IPAddress.Parse("64:ff9b::7f00:1"),
            IPAddress.Parse("64:ff9b::0a00:1"),
            IPAddress.Parse("2002:0a00:0001::"),
            IPAddress.Parse("2001:0000:0000:0000:0000:0000:f5ff:fffe"),
        ];

        for (int i = 0; i < blockedAddresses.Length; i++)
        {
            EndpointGuardResult result = EndpointGuard.Evaluate(
                new Uri("https://provider.example/token"),
                [blockedAddresses[i]]);

            Assert.IsFalse(result.IsAllowed, blockedAddresses[i].ToString());
            Assert.AreEqual(EndpointGuardBlockReason.NonPublicAddress, result.BlockReason);
        }
    }

    /// <summary>
    /// Verifies that test harnesses can explicitly allow non-public endpoints for local fakes.
    /// </summary>
    [TestMethod]
    public void EvaluateAllowsNonPublicAddressesWhenConfigured()
    {
        var options = new EndpointGuardOptions
        {
            AllowNonPublicAddresses = true,
        };

        EndpointGuardResult result = EndpointGuard.Evaluate(
            new Uri("https://127.0.0.1/fake-provider"),
            [IPAddress.Parse("127.0.0.1")],
            options);

        Assert.IsTrue(result.IsAllowed);
    }

    /// <summary>
    /// Verifies that empty DNS results are treated as a failure.
    /// </summary>
    [TestMethod]
    public void EvaluateBlocksEmptyResolvedAddressList()
    {
        EndpointGuardResult result = EndpointGuard.Evaluate(
            new Uri("https://provider.example/token"),
            []);

        Assert.IsFalse(result.IsAllowed);
        Assert.AreEqual(EndpointGuardBlockReason.DnsFailure, result.BlockReason);
    }

    /// <summary>
    /// Verifies that guarded HTTP handlers reject a non-public address resolved at socket-connect time.
    /// </summary>
    [TestMethod]
    [Timeout(5000, CooperativeCancellation = true)]
    public async Task GuardedHttpHandlerBlocksNonPublicAddressResolvedAtConnectTime()
    {
        int resolverCalls = 0;
        using var httpClient = new HttpClient(EndpointGuardHttpHandlerFactory.Create(new EndpointGuardHttpHandlerOptions
        {
            AddressResolver = (_, _) =>
            {
                resolverCalls++;
                return new ValueTask<IPAddress[]>([IPAddress.Loopback]);
            },
        }), disposeHandler: true);

        HttpRequestException exception = await Assert.ThrowsExactlyAsync<HttpRequestException>(
            () => httpClient.GetAsync(new Uri("https://provider.example/token"), TestContext.CancellationToken));

        Assert.Contains("endpoint blocked", exception.Message);
        Assert.AreEqual(1, resolverCalls);
    }
}
