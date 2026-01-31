# Netter HAR Validation Relaxation Design

**Date:** 2026-01-31
**Component:** Netter (HAR to Phishlet Generator)
**Files Affected:** `core/har_parser.go`, `core/netter.go`

## Problem Statement

The current HAR validation logic in the netter function is too strict, causing false negatives. Specifically, the `LoginCandidate` requirement rejects valid HAR files when:

- Login POST sets auth cookies but credentials aren't auto-detected (unusual field names)
- Credentials are detected but the response doesn't set cookies immediately
- Multi-step login flows where cookies are set by a different endpoint than the credential POST

## Current Validation Logic

Located in `core/har_parser.go:419-436`, the validation requires:

1. At least one domain ✓ (keep)
2. At least one POST request (too strict)
3. At least one cookie (too strict)
4. LoginCandidate auto-detected (too strict)

The LoginCandidate must be a POST request that BOTH:
- Contains auto-detected credentials (username + password fields)
- Sets auth cookies in the response

This combination is often not present in real-world HAR files.

## Proposed Solution

### Relaxed Validation

**New minimum requirements:**
- At least one domain (unchanged)
- At least one POST request OR at least one cookie

**Removed requirements:**
- Hard requirement for LoginCandidate auto-detection
- Hard requirement for both POST and cookies

### Fallback to Manual Selection

The interactive prompts in `core/netter.go` already support manual selection:
- `promptManualCredentialSelection()` - lets user choose POST and fields
- `promptManualLoginSelection()` - lets user choose login endpoint

These will be used when auto-detection fails.

## Implementation Changes

### 1. Update Validation (har_parser.go:418-437)

**Before:**
```go
func (a *HARAnalysis) Validate() error {
    if len(a.Domains) == 0 {
        return fmt.Errorf("no domains found...")
    }
    if len(a.PostRequests) == 0 {
        return fmt.Errorf("no POST requests found...")
    }
    if len(a.Cookies) == 0 {
        return fmt.Errorf("no cookies found...")
    }
    if a.LoginCandidate == nil {
        return fmt.Errorf("no login endpoint detected...")
    }
    return nil
}
```

**After:**
```go
func (a *HARAnalysis) Validate() error {
    if len(a.Domains) == 0 {
        return fmt.Errorf("no domains found in HAR file - ensure the HAR contains actual HTTP traffic")
    }

    // Require either POST requests OR cookies (or both)
    if len(a.PostRequests) == 0 && len(a.Cookies) == 0 {
        return fmt.Errorf("no POST requests or cookies found - HAR must contain login flow or session cookies")
    }

    return nil
}
```

### 2. Update promptCredentialsConfirmation (netter.go:173-208)

Handle nil LoginCandidate by showing a message and going directly to manual selection:

```go
func (ng *NetterGenerator) promptCredentialsConfirmation(analysis *HARAnalysis) (*PostRequestInfo, error) {
    if analysis.LoginCandidate == nil {
        log.Warning("No login credentials auto-detected")
        fmt.Fprintf(color.Output, "\n%s\n\n",
            color.YellowString("Could not auto-detect credentials. Please select manually."))
        return ng.promptManualCredentialSelection(analysis)
    }

    // ... rest of existing code unchanged
}
```

### 3. Update promptLoginConfirmation (netter.go:292-322)

Handle nil LoginCandidate similarly:

```go
func (ng *NetterGenerator) promptLoginConfirmation(analysis *HARAnalysis) (*PostRequestInfo, error) {
    if analysis.LoginCandidate == nil {
        log.Warning("No login endpoint auto-detected")
        fmt.Fprintf(color.Output, "\n%s\n\n",
            color.YellowString("Could not auto-detect login endpoint. Please select manually."))
        return ng.promptManualLoginSelection(analysis)
    }

    // ... rest of existing code unchanged
}
```

## Benefits

1. **Fewer false negatives** - More HAR files will pass validation
2. **Better user experience** - Manual selection for edge cases
3. **No breaking changes** - Existing working flows unchanged
4. **Graceful degradation** - Falls back to manual selection when auto-detection fails

## Edge Cases Handled

- **No POST requests:** User can still extract cookies and domains, skip credentials
- **No cookies:** User can still extract login POST and domains
- **No credentials detected:** Manual selection of POST fields
- **No auth cookies set:** Manual selection of login endpoint

## Testing

Existing test `TestNetterE2E` should continue to pass since it has all required components.

Additional manual testing needed:
- HAR with POST but no cookies
- HAR with cookies but no POST
- HAR with unusual credential field names
- Multi-step login flows
