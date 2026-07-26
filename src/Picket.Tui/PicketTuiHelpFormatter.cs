using Hex1b.Input;
using System.Globalization;
using System.Text;

namespace Picket.Tui;

/// <summary>
/// Formats registered scanner-console key bindings for the in-app keyboard reference.
/// </summary>
internal static class PicketTuiHelpFormatter
{
    /// <summary>
    /// Formats the registered bindings for the current scanner-console view.
    /// </summary>
    /// <param name="bindings">The registered root bindings.</param>
    /// <param name="view">The current scanner-console view.</param>
    /// <returns>A grouped keyboard reference.</returns>
    internal static string Format(IReadOnlyList<InputBinding> bindings, PicketTuiView view)
    {
        var shortcutsByDescription = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        var order = new List<string>();
        for (int i = 0; i < bindings.Count; i++)
        {
            InputBinding binding = bindings[i];
            if (string.IsNullOrWhiteSpace(binding.Description))
            {
                continue;
            }

            string description = binding.Description;
            if (!shortcutsByDescription.TryGetValue(description, out List<string>? shortcuts))
            {
                shortcuts = [];
                shortcutsByDescription.Add(description, shortcuts);
                order.Add(description);
            }

            string shortcut = FormatShortcut(binding.Steps);
            if (!shortcuts.Contains(shortcut, StringComparer.Ordinal))
            {
                shortcuts.Add(shortcut);
            }
        }

        var global = new List<(string Shortcut, string Description)>();
        var navigation = new List<(string Shortcut, string Description)>();
        var contextual = new List<(string Shortcut, string Description)>();
        for (int i = 0; i < order.Count; i++)
        {
            string description = order[i];
            string shortcut = string.Join(" / ", shortcutsByDescription[description]);
            (string Shortcut, string Description) entry = (shortcut, description);
            if (IsNavigation(description))
            {
                navigation.Add(entry);
            }
            else if (IsGlobal(description))
            {
                global.Add(entry);
            }
            else
            {
                contextual.Add(entry);
            }
        }

        var builder = new StringBuilder();
        AppendGroup(builder, "Global", global);
        AppendGroup(builder, "Navigation", navigation);
        AppendGroup(builder, PicketTuiState.GetViewLabel(view), contextual);
        builder.AppendLine();
        builder.Append("Esc closes this reference.");
        return builder.ToString();
    }

    private static void AppendGroup(
        StringBuilder builder,
        string title,
        List<(string Shortcut, string Description)> entries)
    {
        if (entries.Count == 0)
        {
            return;
        }

        if (builder.Length != 0)
        {
            builder.AppendLine();
        }

        builder.AppendLine(title);
        for (int i = 0; i < entries.Count; i++)
        {
            (string shortcut, string description) = entries[i];
            builder.Append("  ");
            builder.Append(shortcut.PadRight(18));
            builder.AppendLine(description);
        }
    }

    private static string FormatShortcut(IReadOnlyList<KeyStep> steps)
    {
        var builder = new StringBuilder();
        for (int i = 0; i < steps.Count; i++)
        {
            if (i != 0)
            {
                builder.Append(' ');
            }

            KeyStep step = steps[i];
            if ((step.Modifiers & Hex1bModifiers.Control) != 0)
            {
                builder.Append("Ctrl+");
            }

            if ((step.Modifiers & Hex1bModifiers.Alt) != 0)
            {
                builder.Append("Alt+");
            }

            if ((step.Modifiers & Hex1bModifiers.Shift) != 0)
            {
                builder.Append("Shift+");
            }

            builder.Append(FormatKey(step.Key, step.Modifiers));
        }

        return builder.ToString();
    }

    private static string FormatKey(Hex1bKey key, Hex1bModifiers modifiers)
    {
        if (key == Hex1bKey.OemQuestion)
        {
            return "?";
        }

        if (key is >= Hex1bKey.D0 and <= Hex1bKey.D9)
        {
            return ((int)key - (int)Hex1bKey.D0).ToString(CultureInfo.InvariantCulture);
        }

        string text = key.ToString();
        return modifiers == Hex1bModifiers.None && text.Length == 1
            ? text.ToLowerInvariant()
            : text;
    }

    private static bool IsGlobal(string description)
    {
        return description is "Cancel scan or quit" or "Keyboard help" or "Quit" or "Run scan";
    }

    private static bool IsNavigation(string description)
    {
        return description is "Dashboard"
            or "Files"
            or "Findings"
            or "Logs"
            or "Next control"
            or "Previous control"
            or "Rules"
            or "Scan workspace";
    }
}
