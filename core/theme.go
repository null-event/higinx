package core

import (
	"github.com/fatih/color"
)

// Tokyo Night color theme
// Based on: https://github.com/jiyometrik/tokyonight-windows-terminal
// Colors: Blue #7aa2f7, Purple #bb9af7, Cyan #7dcfff, Green #73daca,
//         Yellow #e0af68, Red #f7768e, White #c0caf5, Black #414868
var (
	// Primary colors - Tokyo Night palette
	ColorPrimary   = color.New(color.FgHiBlue)             // Blue #7aa2f7 - main text
	ColorSecondary = color.New(color.FgBlue)               // Darker blue - secondary
	ColorDim       = color.New(color.FgHiBlack)            // Gray #414868 - timestamps, meta
	ColorAccent    = color.New(color.FgHiMagenta)          // Purple #bb9af7 - highlights, data
	ColorMagenta   = color.New(color.FgHiMagenta)          // Purple #bb9af7 - important notices

	// Status colors
	ColorSuccess = color.New(color.FgHiCyan, color.Bold)   // Teal/Green #73daca - success
	ColorWarning = color.New(color.FgHiYellow)             // Yellow #e0af68 - warnings
	ColorError   = color.New(color.FgHiRed)                // Red #f7768e - errors
	ColorFatal   = color.New(color.FgHiWhite, color.BgRed, color.Bold) // Fatal errors

	// UI element colors
	ColorPrompt    = color.New(color.FgHiBlue, color.Bold)              // Blue #7aa2f7 - command prompt
	ColorInput     = color.New(color.FgHiWhite)                         // White #c0caf5 - user input
	ColorHeader    = color.New(color.FgHiMagenta, color.Bold, color.Underline) // Purple - section headers
	ColorTableHead = color.New(color.FgHiCyan, color.Bold)              // Cyan #7dcfff - table headers
	ColorTableRow  = color.New(color.FgHiBlue)                          // Blue - table rows
	ColorHighlight = color.New(color.FgHiWhite, color.Bold)             // White #c0caf5 - highlighted text
	ColorMuted     = color.New(color.FgHiBlack)                         // Gray #414868 - muted/disabled text

	// Badge/tag colors for log levels
	ColorBadgeDebug   = color.New(color.FgWhite, color.BgHiBlack)
	ColorBadgeInfo    = color.New(color.FgBlack, color.BgHiBlue)
	ColorBadgeImport  = color.New(color.FgBlack, color.BgHiMagenta)
	ColorBadgeWarning = color.New(color.FgBlack, color.BgHiYellow)
	ColorBadgeError   = color.New(color.FgHiWhite, color.BgRed)
	ColorBadgeFatal   = color.New(color.FgHiWhite, color.BgRed, color.Bold)
	ColorBadgeSuccess = color.New(color.FgBlack, color.BgHiCyan)

	// Special colors for session/credential captures
	ColorCapture  = color.New(color.FgHiCyan, color.Bold, color.BlinkSlow) // Teal #73daca - captured credentials
	ColorSession  = color.New(color.FgHiMagenta)                           // Purple #bb9af7 - session info
	ColorToken    = color.New(color.FgHiCyan)                              // Cyan #7dcfff - auth tokens
)

// ASCII Art banner - Matrix style
const MatrixBanner = `
  .__     .__       .__
  |  |__  |__|  ____|__| ____  ___  ___
  |  |  \ |  | / ___\  |/    \ \  \/  /
  |   Y  \|  |/ /_/  > |   |  \ >    <
  |___|  /|__|\___  /|_|___|  //__/\_ \
       \/    /_____/        \/       \/  v%s

`

// Compact banner for smaller terminals
const MatrixBannerCompact = `
╔═══════════════════════════════════════════╗
║  ▓█▀▀▀█▓  HIGINX  ▓█▀▀▀█▓  v%s          ║
╚═══════════════════════════════════════════╝
`

// Animated frame characters for loading effects
var MatrixChars = []rune{'ﾊ', 'ﾐ', 'ﾋ', 'ｰ', 'ｳ', 'ｼ', 'ﾅ', 'ﾓ', 'ﾆ', 'ｻ', 'ﾜ', 'ﾂ', 'ｵ', 'ﾘ', 'ｱ', 'ﾎ', 'ﾃ', 'ﾏ', 'ｹ', 'ﾒ', 'ｴ', 'ｶ', 'ｷ', 'ﾑ', 'ﾕ', 'ﾗ', 'ｾ', 'ﾈ', 'ｽ', 'ﾀ', 'ﾇ', 'ﾍ'}

// Box drawing characters for tables
const (
	BoxTopLeft     = "╔"
	BoxTopRight    = "╗"
	BoxBottomLeft  = "╚"
	BoxBottomRight = "╝"
	BoxHorizontal  = "═"
	BoxVertical    = "║"
	BoxTeeLeft     = "╠"
	BoxTeeRight    = "╣"
	BoxTeeTop      = "╦"
	BoxTeeBottom   = "╩"
	BoxCross       = "╬"
)

// Helper functions for themed output
func Sprint(c *color.Color, format string, a ...interface{}) string {
	return c.Sprintf(format, a...)
}

func Sprimary(format string, a ...interface{}) string {
	return ColorPrimary.Sprintf(format, a...)
}

func Saccent(format string, a ...interface{}) string {
	return ColorAccent.Sprintf(format, a...)
}

func Ssuccess(format string, a ...interface{}) string {
	return ColorSuccess.Sprintf(format, a...)
}

func Swarning(format string, a ...interface{}) string {
	return ColorWarning.Sprintf(format, a...)
}

func Serror(format string, a ...interface{}) string {
	return ColorError.Sprintf(format, a...)
}

func Sdim(format string, a ...interface{}) string {
	return ColorDim.Sprintf(format, a...)
}

func Shighlight(format string, a ...interface{}) string {
	return ColorHighlight.Sprintf(format, a...)
}
