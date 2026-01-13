package core

import (
	"github.com/fatih/color"
)

// Matrix/Mr Robot inspired color theme
var (
	// Primary colors - cyberpunk green palette
	ColorPrimary   = color.New(color.FgHiGreen)           // Bright green - main text
	ColorSecondary = color.New(color.FgGreen)             // Standard green - secondary
	ColorDim       = color.New(color.FgGreen, color.Faint) // Dim green - timestamps, meta
	ColorAccent    = color.New(color.FgHiCyan)            // Cyan - highlights, data
	ColorMagenta   = color.New(color.FgHiMagenta)         // Magenta - important notices

	// Status colors
	ColorSuccess = color.New(color.FgHiGreen, color.Bold) // Success messages
	ColorWarning = color.New(color.FgHiYellow)            // Warnings
	ColorError   = color.New(color.FgHiRed)               // Errors
	ColorFatal   = color.New(color.FgHiWhite, color.BgRed, color.Bold) // Fatal errors

	// UI element colors
	ColorPrompt    = color.New(color.FgHiGreen, color.Bold) // Command prompt
	ColorInput     = color.New(color.FgHiWhite)             // User input
	ColorHeader    = color.New(color.FgHiGreen, color.Bold, color.Underline) // Section headers
	ColorTableHead = color.New(color.FgHiCyan, color.Bold)  // Table headers
	ColorTableRow  = color.New(color.FgGreen)               // Table rows
	ColorHighlight = color.New(color.FgHiWhite, color.Bold) // Highlighted text
	ColorMuted     = color.New(color.FgHiBlack)             // Muted/disabled text

	// Badge/tag colors for log levels
	ColorBadgeDebug   = color.New(color.FgBlack, color.BgHiBlack)
	ColorBadgeInfo    = color.New(color.FgBlack, color.BgGreen)
	ColorBadgeImport  = color.New(color.FgBlack, color.BgHiCyan)
	ColorBadgeWarning = color.New(color.FgBlack, color.BgHiYellow)
	ColorBadgeError   = color.New(color.FgHiWhite, color.BgRed)
	ColorBadgeFatal   = color.New(color.FgHiWhite, color.BgRed, color.Bold)
	ColorBadgeSuccess = color.New(color.FgBlack, color.BgHiGreen)

	// Special colors for session/credential captures
	ColorCapture  = color.New(color.FgHiGreen, color.Bold, color.BlinkSlow) // Captured credentials
	ColorSession  = color.New(color.FgHiMagenta)                            // Session info
	ColorToken    = color.New(color.FgHiCyan)                               // Auth tokens
)

// ASCII Art banner - Matrix style
const MatrixBanner = `
                    .__.__                 .__
  _______  _|__|  |   ____ |__| ____ ___  ___
_/ __ \  \/ /  |  |  / ___\|  |/    \\  \/  /
\  ___/\   /|  |  |_/ /_/  >  |   |  \>    <
 \___  >\_/ |__|____\___  /|__|___|  /__/\_ \
     \/            /_____/         \/      \/  v%s

`

// Compact banner for smaller terminals
const MatrixBannerCompact = `
╔═══════════════════════════════════════════╗
║  ▓█▀▀▀█▓ EVILGINX ▓█▀▀▀█▓  v%s          ║
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
