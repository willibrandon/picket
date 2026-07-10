using Picket.Security;

namespace Picket.Tests;

/// <summary>
/// Tests guarded HTTP handler construction.
/// </summary>
[TestClass]
public sealed class EndpointGuardHttpHandlerFactoryTests
{
    /// <summary>
    /// Verifies that production handlers disable automatic redirects and guard each connection.
    /// </summary>
    [TestMethod]
    public void CreateDisablesAutomaticRedirectsAndGuardsConnections()
    {
        using SocketsHttpHandler handler = EndpointGuardHttpHandlerFactory.Create();

        Assert.IsFalse(handler.AllowAutoRedirect);
        Assert.IsNotNull(handler.ConnectCallback);
    }
}
