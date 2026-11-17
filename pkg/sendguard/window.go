package sendguard

import (
	"fmt"
	"net/netip"
	"slices"
	"time"
)

// Window sizes and bounds of the in-memory per-account sending profile.
const (
	minutesPerDay    = 24 * 60
	baselineHours    = 7 * 24
	warmupPeriod     = 24 * time.Hour
	maxKnownDomains  = 5000
	knownDomainTTL   = 30 * 24 * time.Hour
	maxLoginEvents   = 1000
	maxOutcomeEvents = 10000
	maxSpamEvents    = 100
)

// Heuristic signal names reported in assessments and hold records.
const (
	SignalVolumeSpike = "volume_spike"
	SignalNewDomains  = "new_recipient_domains"
	SignalBounceRate  = "bounce_rate"
	SignalLoginSpread = "login_spread"
	SignalSpamContent = "spam_content"
)

// Heuristic thresholds. Each signal contributes a moderate or a strong score;
// the default compromise threshold needs two independent signals.
const (
	spikeFloorRecipients = 50
	spikeRatio           = 5
	spikeStrongRatio     = 10
	newDomainsModerate   = 10
	newDomainsStrong     = 25
	newDomainsCold       = 50
	bounceMinimumSample  = 10
	bounceRateModerate   = 0.3
	bounceRateStrong     = 0.6
	loginPrefixModerate  = 4
	loginPrefixStrong    = 8
	spamModerate         = 1
	spamStrong           = 3
	pointsModerate       = 30
	pointsSpike          = 40
	pointsStrong         = 50
	pointsSpikeStrong    = 60
)

// Signal is one heuristic's contribution to a compromise assessment.
type Signal struct {
	Name   string  `json:"name"`
	Points float64 `json:"points"`
	Detail string  `json:"detail"`
}

// Assessment is an account's current compromise score.
type Assessment struct {
	Score     float64  `json:"score"`
	Threshold float64  `json:"threshold"`
	Signals   []Signal `json:"signals"`
}

// Usage is an account's submitted volume inside the quota windows.
type Usage struct {
	MessagesHour   int `json:"messages_hour"`
	RecipientsHour int `json:"recipients_hour"`
	RecipientsDay  int `json:"recipients_day"`
}

type minuteBucket struct {
	minute     int64
	messages   int
	recipients int
}

type hourBucket struct {
	hour       int64
	recipients int
}

type timedValue struct {
	at    time.Time
	value string
}

type outcome struct {
	at     time.Time
	failed bool
}

// accountState is one account's sliding-window profile. Minute buckets carry
// the quota windows; hour buckets carry the week-long volume baseline.
type accountState struct {
	firstSeen  time.Time
	releasedAt time.Time
	minutes    [minutesPerDay]minuteBucket
	hours      [baselineHours]hourBucket
	domains    map[string]time.Time
	newDomains []timedValue
	logins     []timedValue
	outcomes   []outcome
	spam       []time.Time
	audited    map[string]time.Time
}

func newAccountState(now time.Time) *accountState {
	return &accountState{firstSeen: now, domains: make(map[string]time.Time), audited: make(map[string]time.Time)}
}

func minuteOf(t time.Time) int64 { return t.Unix() / 60 }

// sum totals messages and recipients over the trailing window of minutes,
// counting only minutes after the one containing since.
func (s *accountState) sum(now time.Time, window int64, since time.Time) (messages, recipients int) {
	current := minuteOf(now)
	floor := current - window
	if !since.IsZero() {
		floor = max(floor, minuteOf(since))
	}
	for _, bucket := range s.minutes {
		if bucket.minute > floor && bucket.minute <= current {
			messages += bucket.messages
			recipients += bucket.recipients
		}
	}
	return messages, recipients
}

// oldestMinute returns the oldest minute with traffic inside the window, so a
// rejection can say when capacity returns.
func (s *accountState) oldestMinute(now time.Time, window int64) int64 {
	current, oldest := minuteOf(now), int64(0)
	for _, bucket := range s.minutes {
		if bucket.minute > current-window && bucket.minute <= current && (bucket.messages > 0 || bucket.recipients > 0) && (oldest == 0 || bucket.minute < oldest) {
			oldest = bucket.minute
		}
	}
	return oldest
}

func (s *accountState) usage(now time.Time) Usage {
	messagesHour, recipientsHour := s.sum(now, 60, time.Time{})
	_, recipientsDay := s.sum(now, minutesPerDay, time.Time{})
	return Usage{MessagesHour: messagesHour, RecipientsHour: recipientsHour, RecipientsDay: recipientsDay}
}

// checkQuota rejects a submission of recipients that would exceed limits.
func (s *accountState) checkQuota(limits Limits, recipients int, now time.Time) *QuotaError {
	usage := s.usage(now)
	retry := func(window int64) time.Duration {
		oldest := s.oldestMinute(now, window)
		if oldest == 0 {
			return time.Minute
		}
		return max(time.Unix((oldest+window)*60, 0).Sub(now), time.Minute)
	}
	switch {
	case limits.MessagesPerHour > 0 && usage.MessagesHour+1 > limits.MessagesPerHour:
		return &QuotaError{Limit: LimitMessagesPerHour, Max: limits.MessagesPerHour, RetryAfter: retry(60)}
	case limits.RecipientsPerHour > 0 && usage.RecipientsHour+recipients > limits.RecipientsPerHour:
		return &QuotaError{Limit: LimitRecipientsPerHour, Max: limits.RecipientsPerHour, RetryAfter: retry(60)}
	case limits.RecipientsPerDay > 0 && usage.RecipientsDay+recipients > limits.RecipientsPerDay:
		return &QuotaError{Limit: LimitRecipientsPerDay, Max: limits.RecipientsPerDay, RetryAfter: retry(minutesPerDay)}
	}
	return nil
}

// record counts one submission and returns its undo.
func (s *accountState) record(now time.Time, recipients int, domains []string) func() {
	minute, hour := minuteOf(now), now.Unix()/3600
	bucket := &s.minutes[minute%minutesPerDay]
	if bucket.minute != minute {
		*bucket = minuteBucket{minute: minute}
	}
	bucket.messages++
	bucket.recipients += recipients
	hourly := &s.hours[hour%baselineHours]
	if hourly.hour != hour {
		*hourly = hourBucket{hour: hour}
	}
	hourly.recipients += recipients
	added := s.learnDomains(now, domains)
	return func() {
		if bucket.minute == minute {
			bucket.messages = max(bucket.messages-1, 0)
			bucket.recipients = max(bucket.recipients-recipients, 0)
		}
		if hourly.hour == hour {
			hourly.recipients = max(hourly.recipients-recipients, 0)
		}
		for _, domain := range added {
			delete(s.domains, domain)
			s.newDomains = slices.DeleteFunc(s.newDomains, func(event timedValue) bool { return event.value == domain && event.at.Equal(now) })
		}
	}
}

// learnDomains remembers recipient domains and logs the ones never seen
// before; it returns the domains it added.
func (s *accountState) learnDomains(now time.Time, domains []string) []string {
	var added []string
	for _, domain := range domains {
		if _, known := s.domains[domain]; known {
			s.domains[domain] = now
			continue
		}
		if len(s.domains) >= maxKnownDomains {
			for name, seen := range s.domains {
				if now.Sub(seen) > knownDomainTTL {
					delete(s.domains, name)
				}
			}
		}
		if len(s.domains) < maxKnownDomains {
			s.domains[domain] = now
			added = append(added, domain)
		}
		s.newDomains = append(trimTimed(s.newDomains, now.Add(-time.Hour)), timedValue{at: now, value: domain})
	}
	return added
}

func (s *accountState) recordLogin(now time.Time, prefix string) {
	s.logins = append(trimTimed(s.logins, now.Add(-time.Hour)), timedValue{at: now, value: prefix})
	if len(s.logins) > maxLoginEvents {
		s.logins = s.logins[len(s.logins)-maxLoginEvents:]
	}
}

func (s *accountState) recordOutcome(now time.Time, failed bool) {
	cutoff := now.Add(-24 * time.Hour)
	index := 0
	for index < len(s.outcomes) && s.outcomes[index].at.Before(cutoff) {
		index++
	}
	s.outcomes = append(s.outcomes[index:], outcome{at: now, failed: failed})
	if len(s.outcomes) > maxOutcomeEvents {
		s.outcomes = s.outcomes[len(s.outcomes)-maxOutcomeEvents:]
	}
}

func (s *accountState) recordSpam(now time.Time) {
	cutoff := now.Add(-time.Hour)
	s.spam = slices.DeleteFunc(s.spam, func(at time.Time) bool { return at.Before(cutoff) })
	s.spam = append(s.spam, now)
	if len(s.spam) > maxSpamEvents {
		s.spam = s.spam[len(s.spam)-maxSpamEvents:]
	}
}

func trimTimed(events []timedValue, cutoff time.Time) []timedValue {
	index := 0
	for index < len(events) && events[index].at.Before(cutoff) {
		index++
	}
	return events[index:]
}

// baseline is the account's average recipients per hour before the current
// hour, over at most a week of history.
func (s *accountState) baseline(now time.Time) float64 {
	current := now.Unix() / 3600
	first := s.firstSeen.Unix() / 3600
	span := min(current-first, baselineHours-1)
	if span <= 0 {
		return 0
	}
	total := 0
	for _, bucket := range s.hours {
		if bucket.hour < current && bucket.hour >= current-span {
			total += bucket.recipients
		}
	}
	return float64(total) / float64(span)
}

// assess scores the account's recent activity. Evidence older than the last
// administrative release is ignored so a release starts a clean window.
func (s *accountState) assess(now time.Time, threshold float64) Assessment {
	assessment := Assessment{Threshold: threshold}
	add := func(name string, points float64, detail string, args ...any) {
		assessment.Signals = append(assessment.Signals, Signal{Name: name, Points: points, Detail: fmt.Sprintf(detail, args...)})
		assessment.Score += points
	}
	hourStart, dayStart := now.Add(-time.Hour), now.Add(-24*time.Hour)
	fresh := func(at, windowStart time.Time) bool { return !at.Before(windowStart) && at.After(s.releasedAt) }
	warm := now.Sub(s.firstSeen) >= warmupPeriod
	_, recipients := s.sum(now, 60, s.releasedAt)
	baseline := s.baseline(now)
	switch {
	case float64(recipients) >= max(2*spikeFloorRecipients, spikeStrongRatio*baseline):
		add(SignalVolumeSpike, pointsSpikeStrong, "%d recipients in the last hour against a baseline of %.1f per hour", recipients, baseline)
	case float64(recipients) >= max(spikeFloorRecipients, spikeRatio*baseline):
		add(SignalVolumeSpike, pointsSpike, "%d recipients in the last hour against a baseline of %.1f per hour", recipients, baseline)
	}
	newDomains := 0
	for _, event := range s.newDomains {
		if fresh(event.at, hourStart) {
			newDomains++
		}
	}
	switch {
	case warm && newDomains >= newDomainsStrong || !warm && newDomains >= newDomainsCold:
		add(SignalNewDomains, pointsStrong, "%d new recipient domains in the last hour", newDomains)
	case warm && newDomains >= newDomainsModerate:
		add(SignalNewDomains, pointsModerate, "%d new recipient domains in the last hour", newDomains)
	}
	total, failed := 0, 0
	for _, event := range s.outcomes {
		if fresh(event.at, dayStart) {
			total++
			if event.failed {
				failed++
			}
		}
	}
	if total >= bounceMinimumSample {
		rate := float64(failed) / float64(total)
		switch {
		case rate >= bounceRateStrong:
			add(SignalBounceRate, pointsStrong, "%d of %d outbound deliveries failed permanently in the last day", failed, total)
		case rate >= bounceRateModerate:
			add(SignalBounceRate, pointsModerate, "%d of %d outbound deliveries failed permanently in the last day", failed, total)
		}
	}
	prefixes := make(map[string]struct{})
	for _, event := range s.logins {
		if fresh(event.at, hourStart) {
			prefixes[event.value] = struct{}{}
		}
	}
	switch {
	case len(prefixes) >= loginPrefixStrong:
		add(SignalLoginSpread, pointsStrong, "logins from %d distinct networks in the last hour", len(prefixes))
	case len(prefixes) >= loginPrefixModerate:
		add(SignalLoginSpread, pointsModerate, "logins from %d distinct networks in the last hour", len(prefixes))
	}
	spam := 0
	for _, at := range s.spam {
		if fresh(at, hourStart) {
			spam++
		}
	}
	switch {
	case spam >= spamStrong:
		add(SignalSpamContent, pointsStrong, "%d outbound messages scored as spam in the last hour", spam)
	case spam >= spamModerate:
		add(SignalSpamContent, pointsModerate, "%d outbound message(s) scored as spam in the last hour", spam)
	}
	return assessment
}

// networkPrefix maps a client address to its /24 (IPv4) or /48 (IPv6)
// network, so one host or one small provider block counts once.
func networkPrefix(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	addr = addr.Unmap().WithZone("")
	bits := 48
	if addr.Is4() {
		bits = 24
	}
	prefix, err := addr.Prefix(bits)
	if err != nil {
		return ""
	}
	return prefix.String()
}
