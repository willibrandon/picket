using Picket.Security;
using Picket.Sources;
using System.Diagnostics.CodeAnalysis;

namespace Picket;

internal static partial class Program
{
    static bool IsHuggingFaceModelFlag(string arg)
    {
        return IsFlag(arg, "--huggingface-model");
    }

    static bool IsHuggingFaceDatasetFlag(string arg)
    {
        return IsFlag(arg, "--huggingface-dataset");
    }

    static bool IsHuggingFaceSpaceFlag(string arg)
    {
        return IsFlag(arg, "--huggingface-space");
    }

    static bool IsHuggingFaceBucketFlag(string arg)
    {
        return IsFlag(arg, "--huggingface-bucket");
    }

    static bool IsHuggingFaceRefFlag(string arg)
    {
        return IsFlag(arg, "--huggingface-ref");
    }

    static bool IsHuggingFacePullRequestFlag(string arg)
    {
        return IsFlag(arg, "--huggingface-pull-request");
    }

    static bool IsHuggingFaceIncludeDiscussionsFlag(string arg)
    {
        return IsFlag(arg, "--huggingface-include-discussions");
    }

    static bool IsHuggingFaceBucketPrefixFlag(string arg)
    {
        return IsFlag(arg, "--huggingface-bucket-prefix");
    }

    static bool IsHuggingFaceTokenEnvironmentVariableFlag(string arg)
    {
        return IsFlag(arg, "--huggingface-token-env");
    }

    static bool IsHuggingFaceEndpointFlag(string arg)
    {
        return IsFlag(arg, "--huggingface-endpoint");
    }

    static bool TryCreateHuggingFaceSourceProvider(
        Uri? endpoint,
        string model,
        string dataset,
        string space,
        string bucket,
        string revision,
        int pullRequestNumber,
        bool includeDiscussions,
        string bucketPrefix,
        string? tokenEnvironmentVariable,
        bool allowNonPublicSourceEndpoints,
        bool allowInsecureSourceEndpoints,
        [NotNullWhen(true)] out NativeSourceProvider? sourceFileProvider)
    {
        sourceFileProvider = null;
        int selectorCount = 0;
        selectorCount += string.IsNullOrWhiteSpace(model) ? 0 : 1;
        selectorCount += string.IsNullOrWhiteSpace(dataset) ? 0 : 1;
        selectorCount += string.IsNullOrWhiteSpace(space) ? 0 : 1;
        selectorCount += string.IsNullOrWhiteSpace(bucket) ? 0 : 1;
        if (selectorCount != 1)
        {
            Console.Error.WriteLine(
                "Hugging Face source scan requires exactly one of --huggingface-model, --huggingface-dataset, --huggingface-space, or --huggingface-bucket");
            return false;
        }

        if (string.IsNullOrWhiteSpace(tokenEnvironmentVariable))
        {
            Console.Error.WriteLine("Hugging Face source scan requires --huggingface-token-env");
            return false;
        }

        string? credential = Environment.GetEnvironmentVariable(tokenEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(credential))
        {
            Console.Error.WriteLine(
                $"Hugging Face token environment variable is not set: {tokenEnvironmentVariable}");
            return false;
        }

        HuggingFaceResourceKind resourceKind;
        string resourceId;
        if (!string.IsNullOrWhiteSpace(model))
        {
            resourceKind = HuggingFaceResourceKind.Model;
            resourceId = model;
        }
        else if (!string.IsNullOrWhiteSpace(dataset))
        {
            resourceKind = HuggingFaceResourceKind.Dataset;
            resourceId = dataset;
        }
        else if (!string.IsNullOrWhiteSpace(space))
        {
            resourceKind = HuggingFaceResourceKind.Space;
            resourceId = space;
        }
        else
        {
            resourceKind = HuggingFaceResourceKind.Bucket;
            resourceId = bucket;
        }

        Uri sourceEndpoint;
        try
        {
            var validatedOptions = new HuggingFaceSourceOptions(
                endpoint ?? HuggingFaceSourceOptions.CreateDefaultEndpoint(),
                resourceKind,
                resourceId,
                credential,
                revision,
                pullRequestNumber,
                includeDiscussions,
                bucketPrefix,
                allowInsecureCredentialTransport: allowInsecureSourceEndpoints);
            sourceEndpoint = validatedOptions.Endpoint;
            resourceKind = validatedOptions.ResourceKind;
            resourceId = validatedOptions.ResourceId;
            revision = validatedOptions.Revision;
            pullRequestNumber = validatedOptions.PullRequestNumber;
            includeDiscussions = validatedOptions.IncludeDiscussions;
            bucketPrefix = validatedOptions.BucketPrefix;
        }
        catch (Exception ex) when (ex is ArgumentException or ArgumentOutOfRangeException)
        {
            Console.Error.WriteLine(ex.Message);
            return false;
        }

        var endpointGuardOptions = new EndpointGuardOptions
        {
            AllowNonPublicAddresses = allowNonPublicSourceEndpoints,
            RequireHttps = !allowInsecureSourceEndpoints,
        };
        EndpointGuardResult endpointGuardResult = EndpointGuard.Evaluate(
            sourceEndpoint,
            endpointGuardOptions);
        if (!endpointGuardResult.IsAllowed)
        {
            Console.Error.WriteLine($"blocked Hugging Face endpoint: {endpointGuardResult.Message}");
            return false;
        }

        sourceFileProvider = (
            _,
            rules,
            maxTargetBytes,
            maxArchiveDepth,
            maxArchiveEntries,
            maxArchiveBytes,
            maxArchiveCompressionRatio,
            timeoutTimestamp,
            cancellationToken) =>
        {
            using var httpClient = new HttpClient(
                EndpointGuardHttpHandlerFactory.Create(new EndpointGuardHttpHandlerOptions
                {
                    EndpointGuardOptions = endpointGuardOptions,
                }),
                disposeHandler: true);
            var client = new HuggingFaceSourceClient(httpClient);
            return client.EnumerateAsync(new HuggingFaceSourceOptions(
                sourceEndpoint,
                resourceKind,
                resourceId,
                credential,
                revision,
                pullRequestNumber,
                includeDiscussions,
                bucketPrefix,
                maxTargetBytes,
                allowInsecureSourceEndpoints,
                maxArchiveDepth,
                maxArchiveEntries,
                maxArchiveBytes,
                maxArchiveCompressionRatio,
                rules.IsGlobalPathAllowed,
                Console.Error.WriteLine,
                () => IsScanStopped(timeoutTimestamp, cancellationToken)),
                cancellationToken).GetAwaiter().GetResult();
        };
        return true;
    }

    private static bool IsFlag(string arg, string name)
    {
        return arg.Equals(name, StringComparison.Ordinal)
            || arg.StartsWith(string.Concat(name, "="), StringComparison.Ordinal);
    }
}
