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
			// Matrix green instead of red
			color.Set(color.BgGreen)
			d = " "
		case "@":
			color.Set(color.BgBlack)
			d = " "
		case "#":
			// Bright green highlights
			color.Set(color.BgHiGreen)
			d = " "
		case "W":
			// Cyan accents instead of white
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
			// Matrix bright green for underscores
			color.Set(color.FgHiGreen)
		case "\n":
			color.Unset()
		default:
			// Matrix dim green for other characters
			color.Set(color.FgGreen)
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
	versionClr := color.New(color.FgHiGreen, color.Bold)
	textClr := color.New(color.FgGreen)
	spc := strings.Repeat(" ", 10-len(VERSION))
	txt := textClr.Sprintf("      by Kuba Gretzky (") + handleClr.Sprintf("@mrgretzky") + textClr.Sprintf(")") + spc + textClr.Sprintf("version ") + versionClr.Sprintf("%s", VERSION)
	fmt.Fprintf(color.Output, "%s", txt)
}

func printOneliner2() {
	textClr := color.New(color.FgGreen)
	accent := color.New(color.FgHiGreen)
	highlight := color.New(color.FgHiCyan)
	txt := textClr.Sprintf("                   no ") + accent.Sprintf("nginx") + highlight.Sprintf(" - ") + textClr.Sprintf("pure ") + accent.Sprintf("evil")
	fmt.Fprintf(color.Output, "%s", txt)
}

func Banner() {
	fmt.Println()

	putAsciiArt("__                                     __\n")
	putAsciiArt("_   @@     @@@@@@@@@@@@@@@@@@@     @@   _")
	printLogo(`    ___________      __ __           __               `)
	fmt.Println()
	putAsciiArt("  @@@@    @@@@@@@@@@@@@@@@@@@@@    @@@@  ")
	printLogo(`    \_   _____/__  _|__|  |    ____ |__| ____ ___  ___`)
	fmt.Println()
	putAsciiArt("  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  ")
	printLogo(`     |    __)_\  \/ /  |  |   / __ \|  |/    \\  \/  /`)
	fmt.Println()
	putAsciiArt("    @@@@@@@@@@###@@@@@@@###@@@@@@@@@@    ")
	printLogo(`     |        \\   /|  |  |__/ /_/  >  |   |  \>    < `)
	fmt.Println()
	putAsciiArt("      @@@@@@@#####@@@@@#####@@@@@@@      ")
	printLogo(`    /_______  / \_/ |__|____/\___  /|__|___|  /__/\_ \`)
	fmt.Println()
	putAsciiArt("       @@@@@@@###@@@@@@@###@@@@@@@       ")
	printLogo(`            \/              /_____/         \/      \/`)
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
