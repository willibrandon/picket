using System.CommandLine;
using System.CommandLine.Help;
using System.CommandLine.Invocation;

namespace Picket;

internal sealed class PicketHelpAction(HelpAction defaultAction) : SynchronousCommandLineAction
{
    private readonly HelpAction _defaultAction = defaultAction;

    public override bool ClearsParseErrors => _defaultAction.ClearsParseErrors;

    public override int Invoke(ParseResult parseResult)
    {
        int exitCode = _defaultAction.Invoke(parseResult);
        WriteSupplementalHelp(parseResult);
        return exitCode;
    }

    private static void WriteSupplementalHelp(ParseResult parseResult)
    {
        Command command = parseResult.CommandResult.Command;
        TextWriter output = parseResult.InvocationConfiguration.Output;

        if (command.Name.Equals("view", StringComparison.Ordinal)
            || command.Name.Equals("tui", StringComparison.Ordinal))
        {
            output.WriteLine("Formats:");
            output.WriteLine("  Picket JSON/JSONL, Gitleaks JSON, TruffleHog JSON/JSONL, GitLab code-quality JSON, SARIF, HTML");
            return;
        }

        if (command.Name.Equals("install", StringComparison.Ordinal) && HasParentCommand(command, "hooks"))
        {
            output.WriteLine("Defaults:");
            output.WriteLine("  Installs pre-commit when no hook name is provided and uses --redact=100 in generated hooks.");
        }
    }

    private static bool HasParentCommand(Command command, string name)
    {
        foreach (Symbol parent in command.Parents)
        {
            if (parent is Command parentCommand && parentCommand.Name.Equals(name, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
