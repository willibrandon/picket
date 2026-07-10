namespace Picket.Tui;

/// <summary>
/// Identifies the scan target source selected in the terminal UI.
/// </summary>
internal enum PicketTuiScanTargetMode
{
    /// <summary>
    /// Scan a local filesystem path.
    /// </summary>
    Local,

    /// <summary>
    /// Scan a GitHub source through native source enumeration.
    /// </summary>
    GitHub,

    /// <summary>
    /// Scan an Azure DevOps source through native source enumeration.
    /// </summary>
    AzureDevOps,

    /// <summary>
    /// Scan a GitLab source through native source enumeration.
    /// </summary>
    GitLab,

    /// <summary>
    /// Scan a Gitea source through native source enumeration.
    /// </summary>
    Gitea,

    /// <summary>
    /// Scan a Bitbucket Cloud source through native source enumeration.
    /// </summary>
    Bitbucket,

    /// <summary>
    /// Scan Amazon S3 or S3-compatible object storage.
    /// </summary>
    S3,

    /// <summary>
    /// Scan Google Cloud Storage objects.
    /// </summary>
    Gcs,

    /// <summary>
    /// Scan Azure Blob Storage objects.
    /// </summary>
    AzureBlob,

    /// <summary>
    /// Scan a local Docker image archive.
    /// </summary>
    DockerArchive,

    /// <summary>
    /// Scan a local OCI image-layout archive.
    /// </summary>
    OciArchive,

    /// <summary>
    /// Scan an OCI or Docker image from a remote registry.
    /// </summary>
    RegistryImage,
}
