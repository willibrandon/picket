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

    private static readonly Hex1bColor s_background = Hex1bColor.FromRgb(18, 20, 28);
    private static readonly Hex1bColor s_border = Hex1bColor.FromRgb(104, 112, 140);
    private static readonly Hex1bColor s_commandForeground = Hex1bColor.FromRgb(224, 187, 92);
    private static readonly Hex1bColor s_errorForeground = Hex1bColor.FromRgb(235, 112, 112);
    private static readonly Hex1bColor s_editorSelectionBackground = Hex1bColor.FromRgb(90, 110, 145);
    private static readonly Hex1bColor s_focusBackground = Hex1bColor.FromRgb(147, 197, 253);
    private static readonly Hex1bColor s_focusForeground = Hex1bColor.FromRgb(10, 15, 24);
    private static readonly Hex1bColor s_focusedRowBackground = Hex1bColor.FromRgb(72, 104, 144);
    private static readonly Hex1bColor s_focusedRowForeground = Hex1bColor.FromRgb(238, 241, 246);
    private static readonly Hex1bColor s_foreground = Hex1bColor.FromRgb(238, 241, 246);
    private static readonly Hex1bColor s_infoForeground = Hex1bColor.FromRgb(86, 220, 206);
    private static readonly Hex1bColor s_mutedForeground = Hex1bColor.FromRgb(168, 174, 194);
    private static readonly Hex1bColor s_panelBackground = Hex1bColor.FromRgb(27, 30, 40);
    private static readonly Hex1bColor s_primaryActionBackground = Hex1bColor.FromRgb(0, 200, 180);
    private static readonly Hex1bColor s_primaryActionForeground = Hex1bColor.Black;
    private static readonly Hex1bColor s_scrollbarThumb = Hex1bColor.FromRgb(166, 178, 210);
    private static readonly Hex1bColor s_successForeground = Hex1bColor.FromRgb(137, 216, 146);
    private static readonly Hex1bColor s_warningForeground = Hex1bColor.FromRgb(232, 185, 92);
    private static readonly Hex1bColor s_yankFlashBackground = Hex1bColor.FromRgb(126, 201, 216);
    private static readonly Hex1bColor s_yankFlashForeground = Hex1bColor.FromRgb(24, 24, 37);
    private static readonly Hex1bColor s_monochromeEmphasisBackground = Hex1bColor.FromRgb(192, 192, 192);
    private static readonly Hex1bColor s_monochromeEmphasisForeground = Hex1bColor.Black;
    private static readonly Hex1bColor s_monochromeFocusBackground = Hex1bColor.White;
    private static readonly Hex1bColor s_monochromeFocusForeground = Hex1bColor.Black;
    private static readonly Hex1bColor s_monochromeSelectionBackground = Hex1bColor.FromRgb(96, 96, 96);
    private static readonly Hex1bColor s_monochromeSelectionForeground = Hex1bColor.White;
    private static readonly Hex1bColor s_monochromeScrollbarThumb = Hex1bColor.FromRgb(160, 160, 160);
    private static bool s_colorEnabled = true;

    /// <summary>
    /// Gets the default application background color.
    /// </summary>
    internal static Hex1bColor Background => Select(s_background, Hex1bColor.Default);

    /// <summary>
    /// Gets the border and separator foreground color.
    /// </summary>
    internal static Hex1bColor Border => Select(s_border, Hex1bColor.Default);

    /// <summary>
    /// Gets the foreground color used for command previews and shell-facing text.
    /// </summary>
    internal static Hex1bColor CommandForeground => Select(s_commandForeground, Hex1bColor.Default);

    /// <summary>
    /// Gets the foreground color used for error state text.
    /// </summary>
    internal static Hex1bColor ErrorForeground => Select(s_errorForeground, Hex1bColor.Default);

    /// <summary>
    /// Gets the read-only editor selection background color.
    /// </summary>
    internal static Hex1bColor EditorSelectionBackground => Select(
        s_editorSelectionBackground,
        s_monochromeSelectionBackground);

    /// <summary>
    /// Gets the focused control background color.
    /// </summary>
    internal static Hex1bColor FocusBackground => Select(s_focusBackground, s_monochromeFocusBackground);

    /// <summary>
    /// Gets the focused control foreground color.
    /// </summary>
    internal static Hex1bColor FocusForeground => Select(s_focusForeground, s_monochromeFocusForeground);

    /// <summary>
    /// Gets the focused table row background color.
    /// </summary>
    internal static Hex1bColor FocusedRowBackground => Select(
        s_focusedRowBackground,
        s_monochromeSelectionBackground);

    /// <summary>
    /// Gets the focused table row foreground color.
    /// </summary>
    internal static Hex1bColor FocusedRowForeground => Select(
        s_focusedRowForeground,
        s_monochromeSelectionForeground);

    /// <summary>
    /// Gets the primary terminal text foreground color.
    /// </summary>
    internal static Hex1bColor Foreground => Select(s_foreground, Hex1bColor.Default);

    /// <summary>
    /// Gets the foreground color used for informational status text.
    /// </summary>
    internal static Hex1bColor InfoForeground => Select(s_infoForeground, Hex1bColor.Default);

    /// <summary>
    /// Gets the muted terminal text foreground color.
    /// </summary>
    internal static Hex1bColor MutedForeground => Select(s_mutedForeground, Hex1bColor.Default);

    /// <summary>
    /// Gets the secondary panel background color.
    /// </summary>
    internal static Hex1bColor PanelBackground => Select(s_panelBackground, Hex1bColor.Default);

    /// <summary>
    /// Gets the background color used for primary actions.
    /// </summary>
    internal static Hex1bColor PrimaryActionBackground => Select(
        s_primaryActionBackground,
        s_monochromeEmphasisBackground);

    /// <summary>
    /// Gets the foreground color used for primary actions.
    /// </summary>
    internal static Hex1bColor PrimaryActionForeground => Select(
        s_primaryActionForeground,
        s_monochromeEmphasisForeground);

    /// <summary>
    /// Gets the table scrollbar thumb color.
    /// </summary>
    internal static Hex1bColor ScrollbarThumb => Select(s_scrollbarThumb, s_monochromeScrollbarThumb);

    /// <summary>
    /// Gets the foreground color used for successful status text.
    /// </summary>
    internal static Hex1bColor SuccessForeground => Select(s_successForeground, Hex1bColor.Default);

    /// <summary>
    /// Gets the foreground color used for warning state text.
    /// </summary>
    internal static Hex1bColor WarningForeground => Select(s_warningForeground, Hex1bColor.Default);

    /// <summary>
    /// Gets the transient yank flash background color.
    /// </summary>
    internal static Hex1bColor YankFlashBackground => Select(
        s_yankFlashBackground,
        s_monochromeEmphasisBackground);

    /// <summary>
    /// Gets the transient yank flash foreground color.
    /// </summary>
    internal static Hex1bColor YankFlashForeground => Select(
        s_yankFlashForeground,
        s_monochromeEmphasisForeground);

    /// <summary>
    /// Determines whether the color palette should be enabled for a <c>NO_COLOR</c> value.
    /// </summary>
    /// <param name="noColor">The value of the <c>NO_COLOR</c> environment variable.</param>
    /// <returns><see langword="true" /> when the color palette should be enabled.</returns>
    internal static bool IsColorEnabled(string? noColor)
    {
        return string.IsNullOrEmpty(noColor);
    }

    /// <summary>
    /// Configures color output from the process environment before the terminal starts rendering.
    /// </summary>
    internal static void ConfigureFromEnvironment()
    {
        s_colorEnabled = IsColorEnabled(Environment.GetEnvironmentVariable("NO_COLOR"));
    }

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
            .Set(DragBarPanelTheme.HandleColor, Border)
            .Set(DragBarPanelTheme.HandleFocusedColor, FocusBackground)
            .Set(DragBarPanelTheme.HandleHoverColor, FocusBackground)
            .Set(DragBarPanelTheme.ThumbColor, ScrollbarThumb)
            .Set(InfoBarTheme.BackgroundColor, PanelBackground)
            .Set(InfoBarTheme.ForegroundColor, Foreground)
            .Set(ListTheme.BackgroundColor, Background)
            .Set(ListTheme.ForegroundColor, Foreground)
            .Set(ListTheme.SelectedBackgroundColor, FocusedRowBackground)
            .Set(ListTheme.SelectedForegroundColor, FocusedRowForeground)
            .Set(ListTheme.HoveredBackgroundColor, PanelBackground)
            .Set(ListTheme.HoveredForegroundColor, Foreground)
            .Set(MenuBarTheme.BackgroundColor, Foreground)
            .Set(MenuBarTheme.ForegroundColor, FocusForeground)
            .Set(MenuBarTheme.FocusedBackgroundColor, Background)
            .Set(MenuBarTheme.FocusedForegroundColor, Foreground)
            .Set(MenuBarTheme.HoveredBackgroundColor, Background)
            .Set(MenuBarTheme.HoveredForegroundColor, Foreground)
            .Set(SplitterTheme.DividerColor, Border)
            .Set(SplitterTheme.FocusedDividerColor, FocusBackground)
            .Set(TableTheme.AlternateRowBackground, Background)
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
            .Set(TableTheme.ScrollbarThumbColor, ScrollbarThumb)
            .Set(TableTheme.ScrollbarTrackColor, Border)
            .Set(TableTheme.TableFocusedBorderColor, Border)
            .Set(TabBarTheme.BackgroundColor, Background)
            .Set(TabBarTheme.ForegroundColor, MutedForeground)
            .Set(TabBarTheme.SelectedBackgroundColor, FocusedRowBackground)
            .Set(TabBarTheme.SelectedForegroundColor, FocusedRowForeground)
            .Set(TabBarTheme.ArrowForegroundColor, MutedForeground)
            .Set(TabBarTheme.ArrowDisabledColor, Background)
            .Set(ToggleSwitchTheme.FocusedSelectedBackgroundColor, FocusedRowBackground)
            .Set(ToggleSwitchTheme.FocusedSelectedForegroundColor, FocusedRowForeground)
            .Set(ToggleSwitchTheme.UnfocusedSelectedBackgroundColor, FocusedRowBackground)
            .Set(ToggleSwitchTheme.UnfocusedSelectedForegroundColor, FocusedRowForeground)
            .Set(ToggleSwitchTheme.UnselectedBackgroundColor, PanelBackground)
            .Set(ToggleSwitchTheme.UnselectedForegroundColor, Foreground)
            .Set(TextBoxTheme.BackgroundColor, PanelBackground)
            .Set(TextBoxTheme.CursorBackgroundColor, FocusBackground)
            .Set(TextBoxTheme.CursorForegroundColor, FocusForeground)
            .Set(TextBoxTheme.FillBackgroundColor, PanelBackground)
            .Set(
                TextBoxTheme.FocusedFillBackgroundColor,
                Select(Hex1bColor.FromRgb(23, 32, 41), Hex1bColor.Default))
            .Set(TextBoxTheme.FocusedForegroundColor, Foreground)
            .Set(TextBoxTheme.ForegroundColor, Foreground)
            .Set(TextBoxTheme.SelectionBackgroundColor, FocusedRowBackground)
            .Set(TextBoxTheme.SelectionForegroundColor, FocusedRowForeground)
            .Set(EditorTheme.SelectionBackgroundColor, EditorSelectionBackground)
            .Set(EditorTheme.SelectionForegroundColor, FocusedRowForeground)
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

    private static Hex1bColor Select(Hex1bColor color, Hex1bColor monochrome)
    {
        return s_colorEnabled ? color : monochrome;
    }
}
