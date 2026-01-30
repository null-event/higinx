package core

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// HAR file structure
type HARFile struct {
	Log struct {
		Entries []HAREntry `json:"entries"`
	} `json:"log"`
}

type HAREntry struct {
	Request  HARRequest  `json:"request"`
	Response HARResponse `json:"response"`
}

type HARRequest struct {
	Method   string       `json:"method"`
	URL      string       `json:"url"`
	Headers  []HARHeader  `json:"headers"`
	PostData *HARPostData `json:"postData"`
}

type HARResponse struct {
	Status  int         `json:"status"`
	Headers []HARHeader `json:"headers"`
	Content HARContent  `json:"content"`
}

type HARHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HARPostData struct {
	MimeType string         `json:"mimeType"`
	Text     string         `json:"text"`
	Params   []HARPostParam `json:"params"`
}

type HARPostParam struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HARContent struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

// Analysis result structures
type HARAnalysis struct {
	Domains        map[string]*DomainInfo
	Cookies        []*CookieInfo
	PostRequests   []*PostRequestInfo
	LoginCandidate *PostRequestInfo
}

type DomainInfo struct {
	OrigDomain    string
	OrigSubdomain string
	BaseDomain    string
	IsLanding     bool
	HasSession    bool
}

type CookieInfo struct {
	Name            string
	Domain          string
	Path            string
	HttpOnly        bool
	Secure          bool
	SetByRequest    string
	IsAuthCandidate bool
}

type PostRequestInfo struct {
	URL              string
	Domain           string
	Path             string
	ContentType      string
	Body             string
	Fields           map[string]string
	SetsAuthCookies  bool
	IsLoginCandidate bool
	AuthCookiesSet   int
	UsernameKey      string
	PasswordKey      string
	PostType         string // "post" or "json"
}

// HARParser parses and analyzes HAR files
type HARParser struct {
	usernamePatterns []*regexp.Regexp
	passwordPatterns []*regexp.Regexp
}

func NewHARParser() *HARParser {
	return &HARParser{
		usernamePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^(email|user|username|login|account|identifier)$`),
		},
		passwordPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)^(pass|password|pwd|passphrase)$`),
		},
	}
}

// ParseFile parses a HAR file and returns analysis
func (p *HARParser) ParseFile(path string) (*HARAnalysis, error) {
	// Read file
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	// Parse JSON
	var harFile HARFile
	if err := json.Unmarshal(data, &harFile); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}

	// Analyze
	return p.analyze(&harFile)
}

func (p *HARParser) analyze(har *HARFile) (*HARAnalysis, error) {
	analysis := &HARAnalysis{
		Domains:      make(map[string]*DomainInfo),
		Cookies:      []*CookieInfo{},
		PostRequests: []*PostRequestInfo{},
	}

	firstDomain := true

	// Process each entry
	for _, entry := range har.Log.Entries {
		// Extract domain
		domain := p.extractDomain(entry.Request.URL)
		if domain != nil {
			if _, exists := analysis.Domains[domain.OrigDomain]; !exists {
				domain.IsLanding = firstDomain
				firstDomain = false
				analysis.Domains[domain.OrigDomain] = domain
			}
		}

		// Extract cookies from response
		cookies := p.extractCookies(&entry, entry.Request.URL)
		analysis.Cookies = append(analysis.Cookies, cookies...)

		if len(cookies) > 0 && domain != nil {
			analysis.Domains[domain.OrigDomain].HasSession = true
		}

		// Extract POST requests
		if entry.Request.Method == "POST" {
			post := p.extractPostRequest(&entry)
			if post != nil {
				analysis.PostRequests = append(analysis.PostRequests, post)
			}
		}
	}

	// Detect login endpoint
	analysis.LoginCandidate = p.detectLogin(analysis)

	return analysis, nil
}

func (p *HARParser) extractDomain(rawURL string) *DomainInfo {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}

	hostname := strings.ToLower(u.Hostname())
	if hostname == "" {
		return nil
	}

	parts := strings.Split(hostname, ".")
	if len(parts) < 2 {
		return nil
	}

	// Simple heuristic: last two parts = base domain
	baseDomain := strings.Join(parts[len(parts)-2:], ".")
	subdomain := ""
	if len(parts) > 2 {
		subdomain = strings.Join(parts[:len(parts)-2], ".")
	}

	return &DomainInfo{
		OrigDomain:    hostname,
		OrigSubdomain: subdomain,
		BaseDomain:    baseDomain,
	}
}

func (p *HARParser) extractCookies(entry *HAREntry, requestURL string) []*CookieInfo {
	var cookies []*CookieInfo

	for _, header := range entry.Response.Headers {
		if strings.ToLower(header.Name) == "set-cookie" {
			cookie := p.parseCookie(header.Value, requestURL)
			if cookie != nil {
				cookies = append(cookies, cookie)
			}
		}
	}

	return cookies
}

func (p *HARParser) parseCookie(setCookieValue, requestURL string) *CookieInfo {
	// Parse Set-Cookie header
	parts := strings.Split(setCookieValue, ";")
	if len(parts) == 0 {
		return nil
	}

	// First part is name=value
	nameValue := strings.SplitN(strings.TrimSpace(parts[0]), "=", 2)
	if len(nameValue) != 2 {
		return nil
	}

	cookie := &CookieInfo{
		Name:   strings.TrimSpace(nameValue[0]),
		Path:   "/",
		Domain: "",
	}

	// Parse attributes
	for i := 1; i < len(parts); i++ {
		attr := strings.TrimSpace(parts[i])
		attrParts := strings.SplitN(attr, "=", 2)
		attrName := strings.ToLower(attrParts[0])

		switch attrName {
		case "domain":
			if len(attrParts) == 2 {
				cookie.Domain = strings.TrimSpace(attrParts[1])
			}
		case "path":
			if len(attrParts) == 2 {
				cookie.Path = strings.TrimSpace(attrParts[1])
			}
		case "httponly":
			cookie.HttpOnly = true
		case "secure":
			cookie.Secure = true
		}
	}

	// If no domain specified, use request domain
	if cookie.Domain == "" {
		u, err := url.Parse(requestURL)
		if err == nil {
			cookie.Domain = "." + u.Hostname()
		}
	}

	cookie.SetByRequest = requestURL

	// Mark as auth candidate if HttpOnly + Secure, or value is long
	value := nameValue[1]
	cookie.IsAuthCandidate = (cookie.HttpOnly && cookie.Secure) || len(value) > 32

	return cookie
}

func (p *HARParser) extractPostRequest(entry *HAREntry) *PostRequestInfo {
	if entry.Request.PostData == nil {
		return nil
	}

	u, err := url.Parse(entry.Request.URL)
	if err != nil {
		return nil
	}

	post := &PostRequestInfo{
		URL:         entry.Request.URL,
		Domain:      u.Hostname(),
		Path:        u.Path,
		ContentType: entry.Request.PostData.MimeType,
		Body:        entry.Request.PostData.Text,
		Fields:      make(map[string]string),
	}

	// Parse POST body based on content type
	if strings.Contains(post.ContentType, "application/x-www-form-urlencoded") {
		post.PostType = "post"
		// Parse from params if available
		for _, param := range entry.Request.PostData.Params {
			post.Fields[param.Name] = param.Value
		}
		// Also try parsing from text
		if len(post.Fields) == 0 && post.Body != "" {
			values, err := url.ParseQuery(post.Body)
			if err == nil {
				for k, v := range values {
					if len(v) > 0 {
						post.Fields[k] = v[0]
					}
				}
			}
		}
	} else if strings.Contains(post.ContentType, "application/json") {
		post.PostType = "json"
		// Parse JSON
		var jsonData map[string]interface{}
		if err := json.Unmarshal([]byte(post.Body), &jsonData); err == nil {
			p.flattenJSON(jsonData, "", post.Fields)
		}
	}

	// Detect credentials
	p.detectCredentials(post)

	// Check if response sets auth cookies
	authCookies := 0
	for _, header := range entry.Response.Headers {
		if strings.ToLower(header.Name) == "set-cookie" {
			cookie := p.parseCookie(header.Value, entry.Request.URL)
			if cookie != nil && cookie.IsAuthCandidate {
				authCookies++
			}
		}
	}

	post.SetsAuthCookies = authCookies > 0
	post.AuthCookiesSet = authCookies

	return post
}

func (p *HARParser) flattenJSON(data map[string]interface{}, prefix string, result map[string]string) {
	for key, value := range data {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}

		switch v := value.(type) {
		case string:
			result[fullKey] = v
		case map[string]interface{}:
			p.flattenJSON(v, fullKey, result)
		default:
			result[fullKey] = fmt.Sprintf("%v", v)
		}
	}
}

func (p *HARParser) detectCredentials(post *PostRequestInfo) {
	var usernameKey, passwordKey string

	for key := range post.Fields {
		// Check for username patterns
		for _, pattern := range p.usernamePatterns {
			if pattern.MatchString(key) {
				usernameKey = key
				break
			}
		}

		// Check for password patterns
		for _, pattern := range p.passwordPatterns {
			if pattern.MatchString(key) {
				passwordKey = key
				break
			}
		}
	}

	if usernameKey != "" && passwordKey != "" {
		post.IsLoginCandidate = true
		post.UsernameKey = usernameKey
		post.PasswordKey = passwordKey
	}
}

func (p *HARParser) detectLogin(analysis *HARAnalysis) *PostRequestInfo {
	// Find POST request with credentials that sets auth cookies
	for _, post := range analysis.PostRequests {
		if post.IsLoginCandidate && post.SetsAuthCookies {
			return post
		}
	}

	// Fallback: find any POST with credentials
	for _, post := range analysis.PostRequests {
		if post.IsLoginCandidate {
			return post
		}
	}

	return nil
}

// Validate checks if the analysis meets minimum requirements
func (a *HARAnalysis) Validate() error {
	if len(a.Domains) == 0 {
		return fmt.Errorf("no domains found in HAR file - ensure the HAR contains actual HTTP traffic")
	}

	if len(a.PostRequests) == 0 {
		return fmt.Errorf("no POST requests found - capture a login flow to generate credentials section")
	}

	if len(a.Cookies) == 0 {
		return fmt.Errorf("no cookies found in responses - ensure the HAR captures Set-Cookie headers")
	}

	if a.LoginCandidate == nil {
		return fmt.Errorf("no login endpoint detected - no POST request contains both credentials and sets auth cookies")
	}

	return nil
}
