using Picket.Engine;
using Picket.Verify;

namespace Picket.Tests;

internal sealed class FakeSecretLiveValidator(
    string provider,
    string version,
    Uri endpoint,
    SecretValidationResult result,
    Func<Finding, bool>? supports = null) : ISecretLiveValidator
{
    private readonly Func<Finding, bool> _supports = supports ?? (_ => true);

    public string Provider { get; } = provider;

    public string Version { get; } = version;

    public Uri Endpoint { get; } = endpoint;

    internal int VerifyCount { get; private set; }

    public bool Supports(Finding finding)
    {
        return _supports(finding);
    }

    public ValueTask<SecretValidationResult> VerifyAsync(Finding finding, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        VerifyCount++;
        return ValueTask.FromResult(result);
    }
}
