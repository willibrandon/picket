namespace Picket.Tui;

/// <summary>
/// Identifies the scan target source selected in the terminal UI.
/// </summary>
internal enum PicketTuiScanTargetMode
{
    /// <summary>
    /// Scan a local filesystem path.
    /// </summary>
    Local = 0,

    /// <summary>
    /// Scan a GitHub source through native source enumeration.
    /// </summary>
    GitHub = 1,

    /// <summary>
    /// Scan an Azure DevOps source through native source enumeration.
    /// </summary>
    AzureDevOps = 2,

    /// <summary>
    /// Scan a GitLab source through native source enumeration.
    /// </summary>
    GitLab = 3,

    /// <summary>
    /// Scan a Gitea source through native source enumeration.
    /// </summary>
    Gitea = 4,

    /// <summary>
    /// Scan a Bitbucket Cloud source through native source enumeration.
    /// </summary>
    Bitbucket = 5,

    /// <summary>
    /// Scan a Bitbucket Data Center source through native source enumeration.
    /// </summary>
    BitbucketDataCenter = 12,

    /// <summary>
    /// Scan Amazon S3 or S3-compatible object storage.
    /// </summary>
    S3 = 6,

    /// <summary>
    /// Scan Google Cloud Storage objects.
    /// </summary>
    Gcs = 7,

    /// <summary>
    /// Scan Azure Blob Storage objects.
    /// </summary>
    AzureBlob = 8,

    /// <summary>
    /// Scan a local Docker image archive.
    /// </summary>
    DockerArchive = 9,

    /// <summary>
    /// Scan a local OCI image-layout archive.
    /// </summary>
    OciArchive = 10,

    /// <summary>
    /// Scan an OCI or Docker image from a remote registry.
    /// </summary>
    RegistryImage = 11,
}
