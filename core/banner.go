package core

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

const (
	VERSION = "3.3.0"
)

func putAsciiArt(s string) {
	for _, c := range s {
		d := string(c)
		switch string(c) {
		case " ":
			// Tokyo Night blue
			color.Set(color.BgHiBlue)
			d = " "
		case "@":
			color.Set(color.BgBlack)
			d = " "
		case "#":
			// Tokyo Night purple highlights
			color.Set(color.BgHiMagenta)
			d = " "
		case "W":
			// Tokyo Night cyan accents
			color.Set(color.BgHiCyan)
			d = " "
		case "_":
			color.Unset()
			d = " "
		case "\n":
			color.Unset()
		}
		fmt.Print(d)
	}
	color.Unset()
}

func printLogo(s string) {
	for _, c := range s {
		d := string(c)
		switch string(c) {
		case "_":
			// Tokyo Night cyan for underscores
			color.Set(color.FgHiCyan)
		case "\n":
			color.Unset()
		default:
			// Tokyo Night blue for other characters
			color.Set(color.FgHiBlue)
		}
		fmt.Print(d)
	}
	color.Unset()
}

func printUpdateName() {
	nameClr := color.New(color.FgHiCyan)
	txt := nameClr.Sprintf("               - --  Community Edition  -- -")
	fmt.Fprintf(color.Output, "%s", txt)
}

func printOneliner1() {
	handleClr := color.New(color.FgHiCyan)
	versionClr := color.New(color.FgHiMagenta, color.Bold)
	textClr := color.New(color.FgHiBlue)
	spc := strings.Repeat(" ", 10-len(VERSION))
	txt := textClr.Sprintf("      by Kuba Gretzky (") + handleClr.Sprintf("@mrgretzky") + textClr.Sprintf(")") + spc + textClr.Sprintf("version ") + versionClr.Sprintf("%s", VERSION)
	fmt.Fprintf(color.Output, "%s", txt)
}

func printOneliner2() {
	textClr := color.New(color.FgHiBlue)
	accent := color.New(color.FgHiMagenta)
	highlight := color.New(color.FgHiCyan)
	txt := textClr.Sprintf("                   no ") + accent.Sprintf("nginx") + highlight.Sprintf(" - ") + textClr.Sprintf("high ") + accent.Sprintf("jinx")
	fmt.Fprintf(color.Output, "%s", txt)
}

func Banner() {
	fmt.Println()

	putAsciiArt("__                                     __\n")
	putAsciiArt("_   @@     @@@@@@@@@@@@@@@@@@@     @@   _")
	printLogo(`      .__     .__       .__                            `)
	fmt.Println()
	putAsciiArt("  @@@@    @@@@@@@@@@@@@@@@@@@@@    @@@@  ")
	printLogo(`      |  |__  |__|  ____|__| ____  ___  ___            `)
	fmt.Println()
	putAsciiArt("  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  ")
	printLogo(`      |  |  \ |  | / ___\  |/    \ \  \/  /            `)
	fmt.Println()
	putAsciiArt("    @@@@@@@@@@###@@@@@@@###@@@@@@@@@@    ")
	printLogo(`      |   Y  \|  |/ /_/  > |   |  \ >    <             `)
	fmt.Println()
	putAsciiArt("      @@@@@@@#####@@@@@#####@@@@@@@      ")
	printLogo(`      |___|  /|__|\___  /|_|___|  //__/\_ \            `)
	fmt.Println()
	putAsciiArt("       @@@@@@@###@@@@@@@###@@@@@@@       ")
	printLogo(`           \/    /_____/        \/       \/            `)
	fmt.Println()
	putAsciiArt("      @@@@@@@@@@@@@@@@@@@@@@@@@@@@@      \n")
	putAsciiArt("     @@@@@WW@@@WW@@WWW@@WW@@@WW@@@@@     ")
	printUpdateName()
	fmt.Println()
	putAsciiArt("    @@@@@@WW@@@WW@@WWW@@WW@@@WW@@@@@@    \n")
	//printOneliner2()
	//fmt.Println()
	putAsciiArt("_   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@   _")
	printOneliner1()
	fmt.Println()
	putAsciiArt("__                                     __\n")
	fmt.Println()
}
