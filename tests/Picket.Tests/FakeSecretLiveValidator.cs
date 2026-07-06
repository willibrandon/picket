using Picket.Engine;
using Picket.Verify;

namespace Picket.Tests;

internal sealed class FakeSecretLiveValidator(
    string provider,
    string version,
    Uri endpoint,
    SecretValidationResult result,
    Func<Finding, bool>? supports = null,
    Func<Finding, CancellationToken, ValueTask<SecretValidationResult>>? verifyAsync = null) : ISecretLiveValidator
{
    private readonly Func<Finding, bool> _supports = supports ?? (_ => true);
    private readonly Func<Finding, CancellationToken, ValueTask<SecretValidationResult>>? _verifyAsync = verifyAsync;
    private int _verifyCount;

    public string Provider { get; } = provider;

    public string Version { get; } = version;

    public Uri Endpoint { get; } = endpoint;

    internal int VerifyCount => Volatile.Read(ref _verifyCount);

    public bool Supports(Finding finding)
    {
        return _supports(finding);
    }

    public ValueTask<SecretValidationResult> VerifyAsync(Finding finding, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Interlocked.Increment(ref _verifyCount);
        if (_verifyAsync is not null)
        {
            return _verifyAsync(finding, cancellationToken);
        }

        return ValueTask.FromResult(result);
    }
}
