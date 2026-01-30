# Netter: Phishlet Generator from HAR Files

**Date:** 2026-01-30
**Status:** Approved for Implementation

## Overview

The `netter` command generates phishlet YAML configurations from HAR (HTTP Archive) files exported from browsers. It performs full traffic analysis, provides interactive selection of authentication tokens and credentials, and outputs valid phishlet configurations ready for use or further refinement.

## Requirements

### Functional Requirements

1. Parse HAR files with strict validation
2. Extract domains, cookies, POST requests, and authentication flows
3. Present interactive prompts for user selection of:
   - Authentication cookies/tokens
   - Login credentials (username/password)
   - Login endpoint URL
4. Generate valid phishlet YAML with:
   - `proxy_hosts` section
   - `auth_tokens` section
   - `credentials` section
   - `login` section
5. Display generated phishlet with option to save to phishlets directory
6. Integrate into higinx terminal as native command

### Non-Functional Requirements

- Strict validation: fail fast with clear errors if HAR lacks required data
- Interactive and user-friendly prompts using readline
- Generate clean, properly formatted YAML
- Add helpful comments to generated phishlets

## Architecture

### Component Structure

```
core/
├── terminal.go            # Modified: add handleNetter() command handler
├── netter.go             # New: orchestration logic
├── har_parser.go         # New: HAR parsing and analysis
└── phishlet_generator.go # New: YAML generation
```

### Command Flow

```
User: netter generate /path/to/file.har

1. terminal.go receives command, calls handleNetter()
2. har_parser.go validates and parses HAR file
3. har_parser.go performs full traffic analysis
4. netter.go presents interactive selections (cookies, credentials, login)
5. phishlet_generator.go builds YAML structure
6. terminal.go displays output, prompts for save
```

## Data Structures

### HARAnalysis (har_parser.go)

```go
type HARAnalysis struct {
    Domains          map[string]*DomainInfo
    Cookies          []*CookieInfo
    PostRequests     []*PostRequestInfo
    LoginCandidate   *LoginInfo
}

type DomainInfo struct {
    OrigDomain       string
    OrigSubdomain    string
    BaseDomain       string
    IsLanding        bool
    HasSession       bool
}

type CookieInfo struct {
    Name             string
    Domain           string
    Path             string
    HttpOnly         bool
    Secure           bool
    SetByRequest     string
    IsAuthCandidate  bool
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
}
```

## Implementation Details

### 1. HAR Parsing (har_parser.go)

**Steps:**
1. Parse JSON into HARFile struct
2. Validate structure (entries exist, non-empty)
3. Extract all domains from request URLs
4. Extract all Set-Cookie headers from responses
5. Parse all POST requests and their bodies
6. Detect login endpoint (POST with credentials that sets auth cookies)
7. Mark auth candidate cookies (HttpOnly + Secure or long values)

**Validation Requirements:**
- At least one domain must be present
- At least one POST request must exist
- At least one cookie must be found
- At least one login candidate must be detected

**Error Messages:**
- "HAR file contains no HTTP entries"
- "No POST requests found - capture a login flow"
- "No cookies found in responses"
- "No login endpoint detected"

### 2. Interactive Selection (netter.go)

**Phase 1: Cookie Selection**
- Display cookies grouped by domain
- Mark likely auth tokens with indicator
- Accept: comma-separated numbers, "all", or "*"
- Validate at least one cookie selected

**Phase 2: Credentials Confirmation**
- Display detected username/password fields
- Show field names, types (json/post)
- Prompt Y/n for confirmation
- Fallback to manual selection if rejected

**Phase 3: Login URL Confirmation**
- Display detected login domain and path
- Show how many auth cookies were set
- Prompt Y/n for confirmation
- Fallback to manual selection if rejected

### 3. Phishlet Generation (phishlet_generator.go)

**Proxy Hosts:**
- One entry per unique domain
- Set session=true if domain sets cookies
- Set is_landing=true for first domain visited
- Always set auto_filter=true

**Auth Tokens:**
- Group selected cookies by domain
- Generate one auth_tokens entry per domain
- Use cookie type (default, omit type field)

**Credentials:**
- Use confirmed username/password field names
- Default search pattern: "(.*)"
- Use detected type (json or post)

**Login:**
- Use confirmed domain and path
- Must match one of the proxy_hosts domains

**Output Format:**
```yaml
min_ver: '3.0.0'
proxy_hosts:
  - {phish_sub: 'accounts', orig_sub: 'accounts', domain: 'example.com', session: true, is_landing: true, auto_filter: true}
auth_tokens:
  - domain: '.accounts.example.com'
    keys: ['session_id', 'csrf_token']
credentials:
  username:
    key: 'email'
    search: '(.*)'
    type: 'json'
  password:
    key: 'password'
    search: '(.*)'
    type: 'json'
login:
  domain: 'accounts.example.com'
  path: '/api/auth/login'
```

### 4. Terminal Integration (terminal.go)

**Add Command Handler:**
```go
case "netter":
    cmd_ok = true
    err := t.handleNetter(args[1:])
    if err != nil {
        log.Error("netter: %v", err)
    }
```

**Methods to Implement:**
- `handleNetter(args)` - Parse command arguments
- `runNetterGenerate(harPath)` - Main orchestration
- `promptCookieSelection(analysis)` - Cookie selection UI
- `promptCredentialsConfirmation(analysis)` - Credentials UI
- `promptLoginConfirmation(analysis)` - Login URL UI
- `promptSavePhishlet(yaml)` - Save prompt and file write

## Edge Cases & Limitations

### Handled
- Multiple domains (generates multiple proxy_hosts)
- JSON vs form-encoded POST data
- Relative vs absolute URLs in HAR
- Cookie domains with/without leading dot
- Empty or malformed HAR files (fail with error)

### Not Handled (Documented Limitations)
- Multi-step authentication (MFA) - uses first POST only
- Dynamic cookie names - user must add :regexp manually
- Complex auth flows (OAuth, SAML)
- Sub-filters generation - relies on auto_filter only
- Custom auth tokens in headers/body - only cookies

## Testing Strategy

**Unit Tests:**
- `har_parser_test.go` - Test parsing valid/invalid HARs
- `phishlet_generator_test.go` - Test YAML generation

**Integration Test:**
- End-to-end test with real HAR fixture
- Verify generated YAML loads with existing phishlet loader

**Manual Testing:**
1. Export HAR from Chrome DevTools during login
2. Run `netter generate test.har`
3. Complete interactive prompts
4. Verify generated phishlet syntax
5. Test with actual proxy (optional)

## Documentation

Add to README.md:

```markdown
### Netter: Phishlet Generator

Generate phishlet configurations from HAR files.

**Prerequisites:**
1. Open Chrome DevTools (F12) → Network tab
2. Clear existing requests
3. Perform complete login flow on target site
4. Right-click → "Save all as HAR with content"

**Usage:**
```
evilginx> netter generate /path/to/capture.har
```

**Limitations:**
- Requires complete authentication flow in HAR
- Does not support multi-step auth automatically
- Generated phishlets may need manual refinement
```

## Implementation Checklist

- [ ] Create har_parser.go with parsing logic
- [ ] Implement domain extraction
- [ ] Implement cookie extraction with auth detection
- [ ] Implement POST parsing (form + JSON)
- [ ] Implement credential pattern matching
- [ ] Implement login endpoint detection
- [ ] Implement validation with clear errors
- [ ] Create phishlet_generator.go
- [ ] Implement all YAML section generation
- [ ] Create netter.go with orchestration
- [ ] Implement terminal integration in terminal.go
- [ ] Implement all interactive prompts
- [ ] Add help text to help.go
- [ ] Write unit tests
- [ ] Write integration tests
- [ ] Update documentation

## Success Criteria

- Successfully parse HAR files from Chrome/Firefox
- Generate valid phishlet YAML that loads without errors
- Interactive prompts work smoothly with readline
- Clear error messages for invalid/incomplete HARs
- Generated phishlets require minimal manual refinement
