namespace Picket.Security;

/// <summary>
/// Represents an outbound endpoint safety decision.
/// </summary>
public sealed class EndpointGuardResult
{
    private EndpointGuardResult(bool isAllowed, EndpointGuardBlockReason blockReason, string message)
    {
        IsAllowed = isAllowed;
        BlockReason = blockReason;
        Message = message ?? string.Empty;
    }

    /// <summary>
    /// Gets a value indicating whether the endpoint is allowed.
    /// </summary>
    public bool IsAllowed { get; }

    /// <summary>
    /// Gets the reason the endpoint was blocked.
    /// </summary>
    public EndpointGuardBlockReason BlockReason { get; }

    /// <summary>
    /// Gets a non-secret diagnostic message.
    /// </summary>
    public string Message { get; }

    /// <summary>
    /// Creates an allowed endpoint decision.
    /// </summary>
    /// <returns>The allowed decision.</returns>
    public static EndpointGuardResult Allow()
    {
        return new EndpointGuardResult(true, EndpointGuardBlockReason.None, "endpoint is allowed");
    }

    /// <summary>
    /// Creates a blocked endpoint decision.
    /// </summary>
    /// <param name="reason">The reason the endpoint was blocked.</param>
    /// <param name="message">A non-secret diagnostic message.</param>
    /// <returns>The blocked decision.</returns>
    public static EndpointGuardResult Block(EndpointGuardBlockReason reason, string message)
    {
        return new EndpointGuardResult(false, reason, message);
    }
}
