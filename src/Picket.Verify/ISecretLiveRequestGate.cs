namespace Picket.Verify;

/// <summary>
/// Executes individual outbound live-validation requests under shared policy.
/// </summary>
internal interface ISecretLiveRequestGate
{
    /// <summary>
    /// Gets the number of provider requests started through this gate.
    /// </summary>
    int RequestCount { get; }

    /// <summary>
    /// Executes one outbound provider request.
    /// </summary>
    /// <typeparam name="T">The request result type.</typeparam>
    /// <param name="request">The provider request to execute.</param>
    /// <param name="cancellationToken">A token that can cancel the request.</param>
    /// <returns>The provider request result.</returns>
    ValueTask<T> ExecuteAsync<T>(
        Func<CancellationToken, ValueTask<T>> request,
        CancellationToken cancellationToken);
}
