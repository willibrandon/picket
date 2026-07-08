namespace Picket.Sources;

/// <summary>
/// Reports that a remote provider metadata response exceeded the scanner safety limit.
/// </summary>
internal sealed class RemoteMetadataTooLargeException(string message) : IOException(message);
