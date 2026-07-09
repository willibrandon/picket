namespace Picket.Tui;

/// <summary>
/// Identifies the scanner-console control that should receive keyboard focus after a view change.
/// </summary>
internal enum PicketTuiFocusTarget
{
    DashboardEditor,
    ScanPrimaryControl,
    FindingsTable,
    RulesTable,
    FilesTable,
    LogsSearch,
}
