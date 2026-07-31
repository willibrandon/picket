using Picket.Rules;
using Scout.Text.Regex;

namespace Picket.Engine;

internal sealed class CompiledRule(
    SecretRule rule,
    ByteRegex? regex,
    ByteRegex? pathRegex,
    List<CompiledAllowlist> allowlists,
    bool usesAwsCredentialPairMatcher,
    bool usesGcpServiceAccountKeyMatcher,
    bool appliesGlobalAllowlists,
    bool deferRegexCompilation,
    string regexContext,
    string pathRegexContext)
{
    private readonly Lock _nativePredicateCompilationLock = new();
    private readonly Lock _regexCompilationLock = new();
    private readonly string _pattern = rule.Pattern;
    private readonly string _pathPattern = rule.PathPattern;
    private readonly bool _deferRegexCompilation = deferRegexCompilation;
    private bool _nativePredicatesCompiled;
    private NativePredicateProgram? _nativeFilter;
    private NativePredicateProgram? _nativePrefilter;
    private ByteRegex? _regex = regex;
    private ByteRegex? _pathRegex = pathRegex;

    internal SecretRule Rule { get; } = rule ?? throw new ArgumentNullException(nameof(rule));

    internal ByteRegex? Regex => UsesAwsCredentialPairMatcher || UsesGcpServiceAccountKeyMatcher ? null : GetRegex(ref _regex, _pattern, regexContext);

    internal ByteRegex? PathRegex => GetRegex(ref _pathRegex, _pathPattern, pathRegexContext);

    internal bool HasContentPattern => _pattern.Length != 0 || UsesAwsCredentialPairMatcher || UsesGcpServiceAccountKeyMatcher;

    internal bool UsesExplicitByteMode => _pattern.Contains("(?-u", StringComparison.Ordinal);

    internal List<CompiledAllowlist> Allowlists { get; } = allowlists ?? throw new ArgumentNullException(nameof(allowlists));

    internal bool UsesAwsCredentialPairMatcher { get; } = usesAwsCredentialPairMatcher;

    internal bool UsesGcpServiceAccountKeyMatcher { get; } = usesGcpServiceAccountKeyMatcher;

    internal bool AppliesGlobalAllowlists { get; } = appliesGlobalAllowlists;

    internal NativePredicateProgram? NativePrefilter
    {
        get
        {
            CompileNativePredicates();
            return _nativePrefilter;
        }
    }

    internal NativePredicateProgram? NativeFilter
    {
        get
        {
            CompileNativePredicates();
            return _nativeFilter;
        }
    }

    internal void CompileNativePredicates()
    {
        if (Volatile.Read(ref _nativePredicatesCompiled))
        {
            return;
        }

        lock (_nativePredicateCompilationLock)
        {
            if (_nativePredicatesCompiled)
            {
                return;
            }

            _nativePrefilter = NativePredicateCompiler.CompileOptional(
                Rule.Prefilter,
                allowFindingFields: false,
                $"{Rule.Id}: prefilter");
            _nativeFilter = NativePredicateCompiler.CompileOptional(
                Rule.Filter,
                allowFindingFields: true,
                $"{Rule.Id}: filter");
            Volatile.Write(ref _nativePredicatesCompiled, true);
        }
    }

    private ByteRegex? GetRegex(ref ByteRegex? regex, string pattern, string context)
    {
        if (pattern.Length == 0)
        {
            return null;
        }

        ByteRegex? compiledRegex = Volatile.Read(ref regex);
        if (compiledRegex is not null || !_deferRegexCompilation)
        {
            return compiledRegex;
        }

        lock (_regexCompilationLock)
        {
            compiledRegex = regex;
            if (compiledRegex is null)
            {
                try
                {
                    compiledRegex = GitleaksRegexCompiler.Compile(pattern);
                    Volatile.Write(ref regex, compiledRegex);
                }
                catch (ByteRegexParseException exception)
                {
                    throw new InvalidDataException($"{context} pattern '{pattern}': {exception.Message}", exception);
                }
            }
        }

        return compiledRegex;
    }
}
