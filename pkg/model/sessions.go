package model

import "time"

// Session represents an active web session (admin login, WebSocket connection, etc.).
type Session struct {
	ID              string    `json:"id"`
	User            string    `json:"user"` // legacy alias for ActorID
	ActorID         string    `json:"actor_id,omitempty"`
	SubjectID       string    `json:"subject_id,omitempty"`
	ActingMode      string    `json:"acting_mode,omitempty"`
	ActingExpiresAt time.Time `json:"acting_expires_at,omitzero"`
	ActingReason    string    `json:"acting_reason,omitempty"`
	CSRFTokenHash   string    `json:"csrf_token_hash,omitempty"`
	IP              string    `json:"ip"`
	UserAgent       string    `json:"user_agent,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	LastActivity    time.Time `json:"last_activity"`
	ExpiresAt       time.Time `json:"expires_at,omitzero"`
	// SecondFactor marks a short-lived sign-in that passed the password check
	// but grants nothing until it completes: "verify" awaits a second factor,
	// "enrol" awaits enrolment required by policy. Empty is a full session.
	SecondFactor         string `json:"second_factor,omitempty"`
	SecondFactorFailures int    `json:"second_factor_failures,omitempty"`
}
