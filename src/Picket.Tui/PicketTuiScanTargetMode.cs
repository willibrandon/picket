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
}
