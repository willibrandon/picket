namespace Picket.Tui;

/// <summary>
/// Identifies the GitHub resource scope selected in the scan workspace.
/// </summary>
internal enum PicketTuiGitHubScope
{
    /// <summary>
    /// Scan one repository.
    /// </summary>
    Repository,

    /// <summary>
    /// Scan repositories visible in one organization.
    /// </summary>
    Organization,

    /// <summary>
    /// Scan repositories owned by one user.
    /// </summary>
    User,

    /// <summary>
    /// Scan one gist.
    /// </summary>
    Gist,

    /// <summary>
    /// Scan gists owned by the authenticated user.
    /// </summary>
    AuthenticatedGists,

    /// <summary>
    /// Scan public gists owned by one user.
    /// </summary>
    UserGists,
}
