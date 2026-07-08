using Hex1b.Theming;

namespace Picket.Tui;

/// <summary>
/// Provides the high-contrast theme used by the Picket terminal UI.
/// </summary>
internal static class PicketTuiPalette
{
    /// <summary>
    /// Minimum contrast ratio for normal terminal text.
    /// </summary>
    internal const double TextContrastMinimum = 4.5;

    /// <summary>
    /// Minimum contrast ratio for terminal UI boundaries and focus indicators.
    /// </summary>
    internal const double UiContrastMinimum = 3.0;

    private static readonly Hex1bColor s_background = Hex1bColor.FromRgb(10, 13, 17);
    private static readonly Hex1bColor s_border = Hex1bColor.FromRgb(82, 96, 112);
    private static readonly Hex1bColor s_commandForeground = Hex1bColor.FromRgb(245, 197, 92);
    private static readonly Hex1bColor s_errorForeground = Hex1bColor.FromRgb(255, 128, 128);
    private static readonly Hex1bColor s_focusBackground = Hex1bColor.FromRgb(0, 200, 180);
    private static readonly Hex1bColor s_focusForeground = Hex1bColor.Black;
    private static readonly Hex1bColor s_focusedRowBackground = Hex1bColor.FromRgb(0, 120, 136);
    private static readonly Hex1bColor s_focusedRowForeground = Hex1bColor.White;
    private static readonly Hex1bColor s_foreground = Hex1bColor.FromRgb(229, 234, 240);
    private static readonly Hex1bColor s_infoForeground = Hex1bColor.FromRgb(120, 232, 216);
    private static readonly Hex1bColor s_mutedForeground = Hex1bColor.FromRgb(166, 176, 186);
    private static readonly Hex1bColor s_panelBackground = Hex1bColor.FromRgb(17, 23, 30);
    private static readonly Hex1bColor s_primaryActionBackground = Hex1bColor.FromRgb(0, 200, 180);
    private static readonly Hex1bColor s_primaryActionForeground = Hex1bColor.Black;
    private static readonly Hex1bColor s_successForeground = Hex1bColor.FromRgb(126, 231, 135);
    private static readonly Hex1bColor s_warningForeground = Hex1bColor.FromRgb(255, 211, 105);
    private static readonly Hex1bColor s_yankFlashBackground = Hex1bColor.FromRgb(242, 211, 92);
    private static readonly Hex1bColor s_yankFlashForeground = Hex1bColor.Black;

    /// <summary>
    /// Gets the default application background color.
    /// </summary>
    internal static Hex1bColor Background => s_background;

    /// <summary>
    /// Gets the border and separator foreground color.
    /// </summary>
    internal static Hex1bColor Border => s_border;

    /// <summary>
    /// Gets the foreground color used for command previews and shell-facing text.
    /// </summary>
    internal static Hex1bColor CommandForeground => s_commandForeground;

    /// <summary>
    /// Gets the foreground color used for error state text.
    /// </summary>
    internal static Hex1bColor ErrorForeground => s_errorForeground;

    /// <summary>
    /// Gets the focused control background color.
    /// </summary>
    internal static Hex1bColor FocusBackground => s_focusBackground;

    /// <summary>
    /// Gets the focused control foreground color.
    /// </summary>
    internal static Hex1bColor FocusForeground => s_focusForeground;

    /// <summary>
    /// Gets the focused table row background color.
    /// </summary>
    internal static Hex1bColor FocusedRowBackground => s_focusedRowBackground;

    /// <summary>
    /// Gets the focused table row foreground color.
    /// </summary>
    internal static Hex1bColor FocusedRowForeground => s_focusedRowForeground;

    /// <summary>
    /// Gets the primary terminal text foreground color.
    /// </summary>
    internal static Hex1bColor Foreground => s_foreground;

    /// <summary>
    /// Gets the foreground color used for informational status text.
    /// </summary>
    internal static Hex1bColor InfoForeground => s_infoForeground;

    /// <summary>
    /// Gets the muted terminal text foreground color.
    /// </summary>
    internal static Hex1bColor MutedForeground => s_mutedForeground;

    /// <summary>
    /// Gets the secondary panel background color.
    /// </summary>
    internal static Hex1bColor PanelBackground => s_panelBackground;

    /// <summary>
    /// Gets the background color used for primary actions.
    /// </summary>
    internal static Hex1bColor PrimaryActionBackground => s_primaryActionBackground;

    /// <summary>
    /// Gets the foreground color used for primary actions.
    /// </summary>
    internal static Hex1bColor PrimaryActionForeground => s_primaryActionForeground;

    /// <summary>
    /// Gets the foreground color used for successful status text.
    /// </summary>
    internal static Hex1bColor SuccessForeground => s_successForeground;

    /// <summary>
    /// Gets the foreground color used for warning state text.
    /// </summary>
    internal static Hex1bColor WarningForeground => s_warningForeground;

    /// <summary>
    /// Gets the transient yank flash background color.
    /// </summary>
    internal static Hex1bColor YankFlashBackground => s_yankFlashBackground;

    /// <summary>
    /// Gets the transient yank flash foreground color.
    /// </summary>
    internal static Hex1bColor YankFlashForeground => s_yankFlashForeground;

    /// <summary>
    /// Applies the Picket high-contrast palette to a Hex1b theme.
    /// </summary>
    /// <param name="theme">The theme to update.</param>
    /// <returns>The updated theme.</returns>
    internal static Hex1bTheme Apply(Hex1bTheme theme)
    {
        return theme
            .Set(GlobalTheme.BackgroundColor, Background)
            .Set(GlobalTheme.ForegroundColor, Foreground)
            .Set(BorderTheme.BorderColor, Border)
            .Set(BorderTheme.TitleColor, Foreground)
            .Set(ButtonTheme.BackgroundColor, PanelBackground)
            .Set(ButtonTheme.ForegroundColor, Foreground)
            .Set(ButtonTheme.FocusedBackgroundColor, FocusBackground)
            .Set(ButtonTheme.FocusedForegroundColor, FocusForeground)
            .Set(ButtonTheme.HoveredBackgroundColor, FocusBackground)
            .Set(ButtonTheme.HoveredForegroundColor, FocusForeground)
            .Set(InfoBarTheme.BackgroundColor, PanelBackground)
            .Set(InfoBarTheme.ForegroundColor, Foreground)
            .Set(ListTheme.BackgroundColor, Background)
            .Set(ListTheme.ForegroundColor, Foreground)
            .Set(ListTheme.SelectedBackgroundColor, FocusedRowBackground)
            .Set(ListTheme.SelectedForegroundColor, FocusedRowForeground)
            .Set(ListTheme.HoveredBackgroundColor, FocusedRowBackground)
            .Set(ListTheme.HoveredForegroundColor, FocusedRowForeground)
            .Set(MenuBarTheme.BackgroundColor, Foreground)
            .Set(MenuBarTheme.ForegroundColor, FocusForeground)
            .Set(MenuBarTheme.FocusedBackgroundColor, Background)
            .Set(MenuBarTheme.FocusedForegroundColor, Foreground)
            .Set(MenuBarTheme.HoveredBackgroundColor, Background)
            .Set(MenuBarTheme.HoveredForegroundColor, Foreground)
            .Set(SplitterTheme.DividerColor, Border)
            .Set(SplitterTheme.FocusedDividerColor, FocusBackground)
            .Set(TableTheme.AlternateRowBackground, PanelBackground)
            .Set(TableTheme.BackgroundColor, Background)
            .Set(TableTheme.BorderColor, Border)
            .Set(TableTheme.EmptyTextForeground, MutedForeground)
            .Set(TableTheme.FocusedBorderColor, Border)
            .Set(TableTheme.FocusedRowBackground, FocusedRowBackground)
            .Set(TableTheme.FocusedRowForeground, FocusedRowForeground)
            .Set(TableTheme.HeaderBackground, PanelBackground)
            .Set(TableTheme.HeaderForeground, Foreground)
            .Set(TableTheme.LoadingTextForeground, MutedForeground)
            .Set(TableTheme.RowBackground, Background)
            .Set(TableTheme.RowForeground, Foreground)
            .Set(TableTheme.ScrollbarThumbColor, Border)
            .Set(TableTheme.ScrollbarTrackColor, Border)
            .Set(TableTheme.TableFocusedBorderColor, Border)
            .Set(TabBarTheme.BackgroundColor, Background)
            .Set(TabBarTheme.ForegroundColor, MutedForeground)
            .Set(TabBarTheme.SelectedBackgroundColor, PrimaryActionBackground)
            .Set(TabBarTheme.SelectedForegroundColor, PrimaryActionForeground)
            .Set(TabBarTheme.ArrowForegroundColor, MutedForeground)
            .Set(TabBarTheme.ArrowDisabledColor, Background)
            .Set(ToggleSwitchTheme.FocusedSelectedBackgroundColor, PrimaryActionBackground)
            .Set(ToggleSwitchTheme.FocusedSelectedForegroundColor, PrimaryActionForeground)
            .Set(ToggleSwitchTheme.UnfocusedSelectedBackgroundColor, PrimaryActionBackground)
            .Set(ToggleSwitchTheme.UnfocusedSelectedForegroundColor, PrimaryActionForeground)
            .Set(ToggleSwitchTheme.UnselectedBackgroundColor, PanelBackground)
            .Set(ToggleSwitchTheme.UnselectedForegroundColor, Foreground)
            .Set(TextBoxTheme.BackgroundColor, PanelBackground)
            .Set(TextBoxTheme.CursorBackgroundColor, FocusBackground)
            .Set(TextBoxTheme.CursorForegroundColor, FocusForeground)
            .Set(TextBoxTheme.FocusedFillBackgroundColor, PanelBackground)
            .Set(TextBoxTheme.FocusedForegroundColor, Foreground)
            .Set(TextBoxTheme.ForegroundColor, Foreground)
            .Set(TextBoxTheme.SelectionBackgroundColor, FocusedRowBackground)
            .Set(ProgressTheme.EmptyForegroundColor, Border)
            .Set(ProgressTheme.FilledForegroundColor, SuccessForeground)
            .Set(ProgressTheme.IndeterminateForegroundColor, InfoForeground);
    }

    /// <summary>
    /// Creates a Hex1b theme with the Picket high-contrast palette applied.
    /// </summary>
    /// <returns>The configured Hex1b theme.</returns>
    internal static Hex1bTheme CreateTheme()
    {
        Hex1bTheme theme = Apply(new Hex1bTheme("Picket"));
        theme.Lock();
        return theme;
    }

    /// <summary>
    /// Calculates the WCAG contrast ratio between two sRGB colors.
    /// </summary>
    /// <param name="first">The first color.</param>
    /// <param name="second">The second color.</param>
    /// <returns>The contrast ratio between the two colors.</returns>
    internal static double ContrastRatio(Hex1bColor first, Hex1bColor second)
    {
        double firstLuminance = RelativeLuminance(first);
        double secondLuminance = RelativeLuminance(second);
        double lighter = Math.Max(firstLuminance, secondLuminance);
        double darker = Math.Min(firstLuminance, secondLuminance);
        return (lighter + 0.05) / (darker + 0.05);
    }

    private static double RelativeLuminance(Hex1bColor color)
    {
        return 0.2126 * Linearize(color.R)
            + 0.7152 * Linearize(color.G)
            + 0.0722 * Linearize(color.B);
    }

    private static double Linearize(byte value)
    {
        double channel = value / 255.0;
        return channel <= 0.04045
            ? channel / 12.92
            : Math.Pow((channel + 0.055) / 1.055, 2.4);
    }
}
