package model

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"
)

// Display preference choices. Empty or "auto" values follow the browser.
var (
	DisplayLanguages    = []string{"en"}
	DisplayTimeFormats  = []string{"auto", "12h", "24h"}
	DisplayDateOrders   = []string{"auto", "dmy", "mdy", "ymd"}
	DisplayDensities    = []string{"compact", "comfortable"}
	DisplayReadingPanes = []string{"right", "bottom", "off"}
)

var clockTime = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)

// DisplayPreferences are the account's web app display settings. They follow
// the signed-in person (the session actor), not a mailbox they work in. The
// zero value means the account has never saved them; Effective supplies the
// defaults and Saved tells the browser to migrate its older local choices.
type DisplayPreferences struct {
	Saved bool `json:"saved,omitempty"`
	// Language is a UI language tag; only "en" exists today.
	Language string `json:"language,omitempty"`
	// TimeZone is an IANA zone name; empty follows the browser.
	TimeZone    string `json:"time_zone,omitempty"`
	TimeFormat  string `json:"time_format,omitempty"`
	DateOrder   string `json:"date_order,omitempty"`
	WeekStart   int    `json:"week_start"`
	WorkingDays []int  `json:"working_days,omitempty"`
	WorkStart   string `json:"work_start,omitempty"`
	WorkEnd     string `json:"work_end,omitempty"`
	Density     string `json:"density,omitempty"`
	ReadingPane string `json:"reading_pane,omitempty"`
}

// DefaultDisplayPreferences returns the settings of an account that never
// saved display preferences.
func DefaultDisplayPreferences() DisplayPreferences {
	return DisplayPreferences{
		Language: "en", TimeFormat: "auto", DateOrder: "auto", WeekStart: 1,
		WorkingDays: []int{1, 2, 3, 4, 5}, WorkStart: "08:00", WorkEnd: "17:00",
		Density: "compact", ReadingPane: "right",
	}
}

// Effective fills unset fields with their defaults.
func (p DisplayPreferences) Effective() DisplayPreferences {
	defaults := DefaultDisplayPreferences()
	if !p.Saved {
		return defaults
	}
	pick := func(value, fallback string) string {
		if value == "" {
			return fallback
		}
		return value
	}
	p.Language = pick(p.Language, defaults.Language)
	p.TimeFormat = pick(p.TimeFormat, defaults.TimeFormat)
	p.DateOrder = pick(p.DateOrder, defaults.DateOrder)
	p.WorkStart = pick(p.WorkStart, defaults.WorkStart)
	p.WorkEnd = pick(p.WorkEnd, defaults.WorkEnd)
	p.Density = pick(p.Density, defaults.Density)
	p.ReadingPane = pick(p.ReadingPane, defaults.ReadingPane)
	if len(p.WorkingDays) == 0 {
		p.WorkingDays = defaults.WorkingDays
	}
	return p
}

// Validate normalizes a complete preference set submitted by the account and
// reports the first invalid field.
func (p *DisplayPreferences) Validate() error {
	choice := func(field, value string, choices []string) error {
		if !slices.Contains(choices, value) {
			return fmt.Errorf("%s must be one of %v", field, choices)
		}
		return nil
	}
	if err := errors.Join(
		choice("language", p.Language, DisplayLanguages),
		choice("time_format", p.TimeFormat, DisplayTimeFormats),
		choice("date_order", p.DateOrder, DisplayDateOrders),
		choice("density", p.Density, DisplayDensities),
		choice("reading_pane", p.ReadingPane, DisplayReadingPanes),
	); err != nil {
		return err
	}
	if p.TimeZone != "" {
		if len(p.TimeZone) > 64 || p.TimeZone == "Local" {
			return errors.New("time_zone must be an IANA time zone name")
		}
		if _, err := time.LoadLocation(p.TimeZone); err != nil {
			return errors.New("time_zone must be an IANA time zone name")
		}
	}
	if p.WeekStart < 0 || p.WeekStart > 6 {
		return errors.New("week_start must be 0 (Sunday) through 6 (Saturday)")
	}
	days := make([]int, 0, len(p.WorkingDays))
	for _, day := range p.WorkingDays {
		if day < 0 || day > 6 {
			return errors.New("working_days must contain days 0 through 6")
		}
		if !slices.Contains(days, day) {
			days = append(days, day)
		}
	}
	if len(days) == 0 {
		return errors.New("choose at least one working day")
	}
	slices.Sort(days)
	p.WorkingDays = days
	if !clockTime.MatchString(p.WorkStart) || !clockTime.MatchString(p.WorkEnd) {
		return errors.New("work_start and work_end must be HH:MM")
	}
	if p.WorkEnd <= p.WorkStart {
		return errors.New("the work day must end after it starts")
	}
	p.Saved = true
	return nil
}

// NotificationPreferences are the account's desktop notification choices.
// Quiet hours suppress desktop notifications and sound between QuietStart
// and QuietEnd (which may wrap midnight) in the display time zone.
type NotificationPreferences struct {
	Saved      bool   `json:"saved,omitempty"`
	NewMail    bool   `json:"new_mail"`
	Favorites  bool   `json:"favorites"`
	Meetings   bool   `json:"meetings"`
	FollowUps  bool   `json:"follow_ups"`
	Sound      bool   `json:"sound"`
	QuietHours bool   `json:"quiet_hours"`
	QuietStart string `json:"quiet_start,omitempty"`
	QuietEnd   string `json:"quiet_end,omitempty"`
}

// DefaultNotificationPreferences notify for new Inbox mail, meeting
// reminders, and follow-up reminders, silently and without quiet hours.
func DefaultNotificationPreferences() NotificationPreferences {
	return NotificationPreferences{NewMail: true, Meetings: true, FollowUps: true, QuietStart: "22:00", QuietEnd: "07:00"}
}

// Effective returns the defaults until the account saves its choices.
func (p NotificationPreferences) Effective() NotificationPreferences {
	if !p.Saved {
		return DefaultNotificationPreferences()
	}
	defaults := DefaultNotificationPreferences()
	if p.QuietStart == "" {
		p.QuietStart = defaults.QuietStart
	}
	if p.QuietEnd == "" {
		p.QuietEnd = defaults.QuietEnd
	}
	return p
}

// Validate checks a submitted preference set.
func (p *NotificationPreferences) Validate() error {
	if !clockTime.MatchString(p.QuietStart) || !clockTime.MatchString(p.QuietEnd) {
		return errors.New("quiet_start and quiet_end must be HH:MM")
	}
	if p.QuietHours && p.QuietStart == p.QuietEnd {
		return errors.New("quiet hours must start and end at different times")
	}
	p.Saved = true
	return nil
}

// UpdateDisplayPreferences replaces the user's display settings.
func (us *UserStore) UpdateDisplayPreferences(ctx context.Context, userID string, preferences DisplayPreferences) error {
	return us.Update(ctx, normalizeID(userID), func(user *User) { user.DisplayPreferences = preferences })
}

// UpdateNotificationPreferences replaces the user's notification settings.
func (us *UserStore) UpdateNotificationPreferences(ctx context.Context, userID string, preferences NotificationPreferences) error {
	return us.Update(ctx, normalizeID(userID), func(user *User) { user.NotificationPreferences = preferences })
}
