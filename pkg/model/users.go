package model

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/lkarlslund/veksel/pkg/auth"
	"github.com/lkarlslund/veksel/pkg/store"
)

var ErrLastSystemOwner = errors.New("cannot disable or delete the last enabled system owner")

// ErrDirectoryPassword refuses a local password for a directory account,
// whose password is changed in the directory.
var ErrDirectoryPassword = errors.New("this account's password is managed by the directory")

// UserStore provides typed CRUD for User and EmailAddress entities.
type UserStore struct {
	ts           *TypedStore
	users        collection[User]
	oauthClients collection[OAuth2Client]
	resets       collection[PasswordResetToken]
}

// NewUserStore returns a UserStore backed by ts.
func NewUserStore(ts *TypedStore) *UserStore {
	return &UserStore{
		ts:           ts,
		users:        newCollection[User](ts, NSUsers),
		oauthClients: newCollection[OAuth2Client](ts, NSOAuth2Clients),
		resets:       newCollection[PasswordResetToken](ts, NSPasswordResets),
	}
}

// Create stores a new user. The password is hashed with bcrypt before storage.
// Returns store.ErrExists if the user already exists.
func (us *UserStore) Create(ctx context.Context, id, displayName, password string) error {
	passwordHash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	return us.CreateUser(ctx, User{ID: id, DisplayName: displayName, PasswordHash: passwordHash})
}

// CreateUser stores a new enabled user from u's ID, display name, password
// hash, directory source, and quota, applying account defaults to everything
// else.
// Returns store.ErrExists if the user already exists.
func (us *UserStore) CreateUser(ctx context.Context, u User) error {
	now := time.Now().UTC()
	u = User{
		ID: normalizeID(u.ID), DisplayName: u.DisplayName, PasswordHash: u.PasswordHash,
		Source: u.Source, DirectoryDN: u.DirectoryDN, DirectoryID: u.DirectoryID,
		MaxStorageBytes: u.MaxStorageBytes, MaxItems: u.MaxItems,
		SpamEnabled: true, Enabled: true,
		CreatedAt: now, UpdatedAt: now,
	}
	return us.users.put(ctx, u.ID, u)
}

// Get returns a user by ID.
func (us *UserStore) Get(ctx context.Context, id string) (User, error) {
	return us.users.get(ctx, normalizeID(id))
}

// ErrResourceAccount refuses a credential or sign-in for a room or equipment
// account, which is non-interactive by design.
var ErrResourceAccount = errors.New("resource accounts are non-interactive and cannot have credentials; manage the calendar through sharing")

// RequireInteractive returns the account and ErrResourceAccount when it is a
// bookable resource, which never signs in, holds credentials, or enrols a
// second factor.
func (us *UserStore) RequireInteractive(ctx context.Context, id string) (User, error) {
	user, err := us.Get(ctx, id)
	if err != nil {
		return User{}, err
	}
	if user.Resource != nil {
		return User{}, ErrResourceAccount
	}
	return user, nil
}

// Update modifies an existing user.
func (us *UserStore) Update(ctx context.Context, id string, fn func(*User)) error {
	return store.Batch(ctx, us.ts.Store(), func(batchCtx context.Context) error {
		u, err := us.Get(batchCtx, id)
		if err != nil {
			return err
		}
		wasEnabled, passwordHash := u.Enabled, u.PasswordHash
		fn(&u)
		if u.Directory() && u.PasswordHash != passwordHash {
			return ErrDirectoryPassword
		}
		if wasEnabled && !u.Enabled {
			if err := us.requireAnotherSystemOwner(batchCtx, u.ID); err != nil {
				return err
			}
		}
		u.UpdatedAt = time.Now().UTC()
		return us.users.set(batchCtx, u.ID, u)
	})
}

// Delete removes a user.
func (us *UserStore) Delete(ctx context.Context, id string) error {
	id = normalizeID(id)
	if err := us.requireAnotherSystemOwner(ctx, id); err != nil {
		return err
	}
	if err := us.users.delete(ctx, id); err != nil {
		return err
	}
	// A later account reusing the ID must not inherit sign-in factors,
	// roles, grants, or group memberships.
	if err := us.ts.Delete(ctx, NSSecondFactors, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return us.forgetPrincipal(ctx, id)
}

// forgetPrincipal removes the policy bindings held by the user id and its
// group memberships.
func (us *UserStore) forgetPrincipal(ctx context.Context, id string) error {
	policies := NewPolicyStore(us.ts)
	bindings, err := policies.ListForPrincipal(ctx, PrincipalRef{Kind: PrincipalUser, ID: id})
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("list bindings of deleted account: %w", err)
	}
	for _, binding := range bindings {
		if err := policies.Delete(ctx, binding.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("delete binding of deleted account: %w", err)
		}
	}
	groups := NewGroupStore(us.ts)
	memberships, err := groups.ListForUser(ctx, id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("list groups of deleted account: %w", err)
	}
	for _, group := range memberships {
		group.Members = slices.DeleteFunc(group.Members, func(member string) bool { return member == id })
		if err := groups.Set(ctx, group); err != nil {
			return fmt.Errorf("leave group %s: %w", group.ID, err)
		}
	}
	return nil
}

func (us *UserStore) requireAnotherSystemOwner(ctx context.Context, userID string) error {
	bindings, err := us.ts.List(ctx, NSPolicyBindings)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil // Authorization has not been initialized on this legacy store.
		}
		return fmt.Errorf("check system owners: %w", err)
	}
	isOwner := false
	otherOwner := false
	now := time.Now().UTC()
	for _, id := range bindings {
		var binding PolicyBinding
		if err := us.ts.Get(ctx, NSPolicyBindings, id, &binding); err != nil || binding.Effect != EffectAllow || binding.RoleID != "system.owner" || binding.Resource != (ResourceRef{Kind: ResourceSystem, ID: SystemResourceID}) || binding.Principal.Kind != PrincipalUser || (!binding.ExpiresAt.IsZero() && !binding.ExpiresAt.After(now)) {
			continue
		}
		if binding.Principal.ID == userID {
			isOwner = true
			continue
		}
		user, err := us.Get(ctx, binding.Principal.ID)
		if err == nil && user.Enabled {
			otherOwner = true
		}
	}
	if isOwner && !otherOwner {
		return ErrLastSystemOwner
	}
	return nil
}

// List returns all users.
func (us *UserStore) List(ctx context.Context) ([]User, error) {
	return us.users.filter(ctx, keepAll)
}

// AddEmailAddress adds an email address for a user, updating all three indexes.
func (us *UserStore) AddEmailAddress(ctx context.Context, addr, userID, domainID string, primary bool) error {
	userID = normalizeID(userID)
	domainID = normalizeID(domainID)
	addr = strings.ToLower(strings.TrimSpace(addr))

	// Extract local part.
	localPart := addr
	if at := strings.Index(addr, "@"); at >= 0 {
		localPart = addr[:at]
	}

	ea := EmailAddress{
		ID:        addr,
		UserID:    userID,
		DomainID:  domainID,
		LocalPart: localPart,
		Primary:   primary,
		Enabled:   true,
		CreatedAt: time.Now().UTC(),
	}

	return store.Batch(ctx, us.ts.Store(), func(batchCtx context.Context) error {
		if _, err := us.ts.RecipientAliasStore().Get(batchCtx, addr); err == nil {
			return fmt.Errorf("email identity conflicts with recipient alias %s", addr)
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if err := us.ts.Put(batchCtx, NSEmails, EmailAddrKey(addr), ea); err != nil {
			return err
		}
		addrs, _ := us.ts.StringList(batchCtx, NSEmails, EmailUserKey(userID))
		addrs = append(addrs, addr)
		slices.Sort(addrs)
		addrs = slices.Compact(addrs)
		if err := us.ts.SetStringList(batchCtx, NSEmails, EmailUserKey(userID), addrs); err != nil {
			return err
		}
		dAddrs, _ := us.ts.StringList(batchCtx, NSEmails, EmailDomainKey(domainID))
		dAddrs = append(dAddrs, addr)
		slices.Sort(dAddrs)
		dAddrs = slices.Compact(dAddrs)
		if err := us.ts.SetStringList(batchCtx, NSEmails, EmailDomainKey(domainID), dAddrs); err != nil {
			return err
		}
		preferred := ""
		if primary {
			preferred = addr
		}
		return us.reconcilePrimaryEmail(batchCtx, userID, preferred)
	})
}

// UpdateEmailAddress changes mutable delivery state while keeping the address,
// owner, and domain indexes immutable. Selecting a primary identity is atomic
// with clearing the previous one.
func (us *UserStore) UpdateEmailAddress(ctx context.Context, addr string, enabled, primary bool) error {
	addr = strings.ToLower(strings.TrimSpace(addr))
	if primary && !enabled {
		return errors.New("a disabled email identity cannot be primary")
	}
	return store.Batch(ctx, us.ts.Store(), func(batchCtx context.Context) error {
		ea, err := us.GetEmailAddress(batchCtx, addr)
		if err != nil {
			return err
		}
		if !enabled {
			references, referenceErr := us.ts.RecipientAliasStore().Referencing(batchCtx, addr)
			if referenceErr != nil {
				return referenceErr
			}
			if len(references) > 0 {
				return fmt.Errorf("%w: %s", ErrRecipientAliasReferenced, references[0].Address)
			}
		}
		ea.Enabled = enabled
		if !enabled {
			ea.Primary = false
		}
		if err := us.ts.Set(batchCtx, NSEmails, EmailAddrKey(addr), ea); err != nil {
			return err
		}
		preferred := ""
		if primary {
			preferred = addr
		}
		return us.reconcilePrimaryEmail(batchCtx, ea.UserID, preferred)
	})
}

func (us *UserStore) reconcilePrimaryEmail(ctx context.Context, userID, preferred string) error {
	addresses, err := us.ts.StringList(ctx, NSEmails, EmailUserKey(normalizeID(userID)))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	slices.Sort(addresses)
	identities := make([]EmailAddress, 0, len(addresses))
	target := ""
	for _, address := range addresses {
		identity, getErr := us.GetEmailAddress(ctx, address)
		if getErr != nil {
			if errors.Is(getErr, store.ErrNotFound) {
				continue
			}
			return getErr
		}
		identities = append(identities, identity)
		if identity.Enabled && identity.ID == preferred {
			target = identity.ID
		}
	}
	if target == "" {
		for _, identity := range identities {
			if identity.Enabled && identity.Primary {
				target = identity.ID
				break
			}
		}
	}
	if target == "" {
		for _, identity := range identities {
			if identity.Enabled {
				target = identity.ID
				break
			}
		}
	}
	for _, identity := range identities {
		wantPrimary := identity.Enabled && identity.ID == target
		if identity.Primary == wantPrimary {
			continue
		}
		identity.Primary = wantPrimary
		if err := us.ts.Set(ctx, NSEmails, EmailAddrKey(identity.ID), identity); err != nil {
			return err
		}
	}
	return nil
}

// GetEmailAddress looks up an email address by its full address.
func (us *UserStore) GetEmailAddress(ctx context.Context, addr string) (EmailAddress, error) {
	var ea EmailAddress
	if err := us.ts.Get(ctx, NSEmails, EmailAddrKey(addr), &ea); err != nil {
		return ea, err
	}
	return ea, nil
}

// ListEmailAddressesForUser returns all addresses belonging to a user.
func (us *UserStore) ListEmailAddressesForUser(ctx context.Context, userID string) ([]EmailAddress, error) {
	addrs, err := us.ts.StringList(ctx, NSEmails, EmailUserKey(normalizeID(userID)))
	if err != nil {
		return nil, err
	}
	var result []EmailAddress
	for _, a := range addrs {
		ea, err := us.GetEmailAddress(ctx, a)
		if err != nil {
			continue
		}
		result = append(result, ea)
	}
	return result, nil
}

// ListEmailAddressesForDomain returns all addresses on a domain.
func (us *UserStore) ListEmailAddressesForDomain(ctx context.Context, domainID string) ([]EmailAddress, error) {
	addrs, err := us.ts.StringList(ctx, NSEmails, EmailDomainKey(normalizeID(domainID)))
	if err != nil {
		return nil, err
	}
	var result []EmailAddress
	for _, a := range addrs {
		ea, err := us.GetEmailAddress(ctx, a)
		if err != nil {
			continue
		}
		result = append(result, ea)
	}
	return result, nil
}

// DeleteEmailAddress removes an address and cleans up indexes.
func (us *UserStore) DeleteEmailAddress(ctx context.Context, addr string) error {
	addr = strings.ToLower(strings.TrimSpace(addr))
	return store.Batch(ctx, us.ts.Store(), func(batchCtx context.Context) error {
		ea, err := us.GetEmailAddress(batchCtx, addr)
		if err != nil {
			return err
		}
		references, err := us.ts.RecipientAliasStore().Referencing(batchCtx, addr)
		if err != nil {
			return err
		}
		if len(references) > 0 {
			return fmt.Errorf("%w: %s", ErrRecipientAliasReferenced, references[0].Address)
		}
		if domainID, err := us.ts.DomainStore().catchAllDomain(batchCtx, addr); err != nil {
			return err
		} else if domainID != "" {
			return fmt.Errorf("%w: email identity is the catch-all target of %s", ErrCatchAllInvalid, domainID)
		}
		if err := us.ts.Delete(batchCtx, NSEmails, EmailAddrKey(addr)); err != nil {
			return err
		}
		addrs, _ := us.ts.StringList(batchCtx, NSEmails, EmailUserKey(ea.UserID))
		filtered := make([]string, 0, len(addrs))
		for _, existing := range addrs {
			if existing != addr {
				filtered = append(filtered, existing)
			}
		}
		if err := us.ts.SetStringList(batchCtx, NSEmails, EmailUserKey(ea.UserID), filtered); err != nil {
			return err
		}
		dAddrs, _ := us.ts.StringList(batchCtx, NSEmails, EmailDomainKey(ea.DomainID))
		dFiltered := make([]string, 0, len(dAddrs))
		for _, existing := range dAddrs {
			if existing != addr {
				dFiltered = append(dFiltered, existing)
			}
		}
		if err := us.ts.SetStringList(batchCtx, NSEmails, EmailDomainKey(ea.DomainID), dFiltered); err != nil {
			return err
		}
		if err := us.Update(batchCtx, ea.UserID, func(user *User) { delete(user.MailSignatures, addr) }); err != nil {
			return err
		}
		return us.reconcilePrimaryEmail(batchCtx, ea.UserID, "")
	})
}

// UpdateMailSignature replaces one owned identity's composer preferences.
func (us *UserStore) UpdateMailSignature(ctx context.Context, userID, address string, signature MailSignature) error {
	userID, address = normalizeID(userID), strings.ToLower(strings.TrimSpace(address))
	identity, err := us.GetEmailAddress(ctx, address)
	if err != nil {
		return err
	}
	if identity.UserID != userID || !identity.Enabled {
		return store.ErrNotFound
	}
	return us.Update(ctx, userID, func(user *User) {
		if user.MailSignatures == nil {
			user.MailSignatures = make(map[string]MailSignature)
		}
		if signature.Text == "" && signature.HTML == "" {
			delete(user.MailSignatures, address)
			return
		}
		user.MailSignatures[address] = signature
	})
}

// MaxRemoteImageSenders bounds the per-user remote image allowlist.
const MaxRemoteImageSenders = 1000

// SetRemoteImageSender adds or removes one sender from the user's remote
// image allowlist and returns the resulting list.
func (us *UserStore) SetRemoteImageSender(ctx context.Context, userID, sender string, allowed bool) ([]string, error) {
	sender = strings.ToLower(strings.TrimSpace(sender))
	list := func(user *User) *[]string { return &user.RemoteImageSenders }
	return us.setListMember(ctx, userID, list, sender, allowed, true, MaxRemoteImageSenders, "senders can always show images")
}

// MaxFavoriteContacts bounds the per-user starred contact list.
const MaxFavoriteContacts = 200

// SetContactFavorite stars or unstars one contact item ID and returns the
// resulting favorite list in starring order.
func (us *UserStore) SetContactFavorite(ctx context.Context, userID, itemID string, favorite bool) ([]string, error) {
	list := func(user *User) *[]string { return &user.FavoriteContacts }
	return us.setListMember(ctx, userID, list, strings.TrimSpace(itemID), favorite, false, MaxFavoriteContacts, "contacts can be favorites")
}

// setListMember adds or removes value in one bounded per-user string list,
// keeping it sorted or in insertion order.
func (us *UserStore) setListMember(ctx context.Context, userID string, list func(*User) *[]string, value string, add, sorted bool, maximum int, noun string) ([]string, error) {
	var result []string
	var limitErr error
	err := us.Update(ctx, normalizeID(userID), func(user *User) {
		target := list(user)
		values := slices.DeleteFunc(slices.Clone(*target), func(candidate string) bool { return candidate == value })
		if add {
			if len(values) >= maximum {
				limitErr = fmt.Errorf("at most %d %s", maximum, noun)
				result = *target
				return
			}
			values = append(values, value)
			if sorted {
				slices.Sort(values)
			}
		}
		*target = values
		result = values
	})
	if err == nil {
		err = limitErr
	}
	return result, err
}

// UpdateCategories replaces the user's master category list.
func (us *UserStore) UpdateCategories(ctx context.Context, userID string, categories []Category) error {
	return us.Update(ctx, normalizeID(userID), func(user *User) { user.Categories = categories })
}

// UpdateMailPreferences replaces the user's webmail behavior settings.
func (us *UserStore) UpdateMailPreferences(ctx context.Context, userID string, preferences MailPreferences) error {
	return us.Update(ctx, normalizeID(userID), func(user *User) { user.MailPreferences = preferences })
}

// UpdateSieveScript updates the user's Sieve script and active flag.
func (us *UserStore) UpdateSieveScript(ctx context.Context, id string, script string, active bool) error {
	return us.Update(ctx, id, func(u *User) {
		u.SieveScript = script
		u.SieveActive = active
	})
}

// GetSieveScript returns the user's Sieve script and active flag.
func (us *UserStore) GetSieveScript(ctx context.Context, id string) (string, bool, error) {
	u, err := us.Get(ctx, id)
	if err != nil {
		return "", false, err
	}
	return u.SieveScript, u.SieveActive, nil
}

// UpdateForwarding updates the user's mail forwarding address.
func (us *UserStore) UpdateForwarding(ctx context.Context, id string, forwardTo string) error {
	return us.Update(ctx, id, func(u *User) {
		u.ForwardTo = forwardTo
	})
}

// UpdateVacation updates the user's vacation auto-reply settings.
func (us *UserStore) UpdateVacation(ctx context.Context, id string, enabled bool,
	start, end time.Time, subject, message string) error {
	return us.Update(ctx, id, func(u *User) {
		u.VacationEnabled = enabled
		u.VacationStart = start
		u.VacationEnd = end
		u.VacationSubject = subject
		u.VacationMessage = message
	})
}

// VacationActive checks whether the user's vacation auto-reply is currently
// active based on enabled flag and date range.
func (u User) VacationActive() bool {
	if !u.VacationEnabled || u.VacationMessage == "" {
		return false
	}
	now := time.Now().UTC()
	if !u.VacationStart.IsZero() && now.Before(u.VacationStart) {
		return false
	}
	if !u.VacationEnd.IsZero() && now.After(u.VacationEnd) {
		return false
	}
	return true
}

// RecordVacationReply stores a timestamp for a sender to enforce rate limiting.
func (us *UserStore) RecordVacationReply(ctx context.Context, userID, sender string) error {
	key := vacationReplyKey(userID, sender)
	now := time.Now().UTC()
	return us.ts.Set(ctx, NSVacationReplies, key, now)
}

// LastVacationReply returns the last time we sent a vacation reply to this sender.
// Returns zero time if no reply has been sent.
func (us *UserStore) LastVacationReply(ctx context.Context, userID, sender string) (time.Time, error) {
	state, err := us.vacationReplyState(ctx, vacationReplyKey(userID, sender))
	return state.LastSent, err
}

const vacationReservationLease = 5 * time.Minute

type vacationReplyState struct {
	LastSent   time.Time `json:"last_sent,omitzero"`
	ReservedAt time.Time `json:"reserved_at,omitzero"`
	Token      string    `json:"token,omitempty"`
}

func vacationReplyKey(userID, sender string) string {
	return strings.ToLower(strings.TrimSpace(userID)) + ":" + strings.ToLower(strings.Trim(strings.TrimSpace(sender), "<>"))
}

func (us *UserStore) vacationReplyState(ctx context.Context, key string) (vacationReplyState, error) {
	data, err := us.ts.Store().Get(ctx, NSVacationReplies, key)
	if err != nil {
		return vacationReplyState{}, err
	}
	var state vacationReplyState
	if err := json.Unmarshal(data, &state); err == nil && (!state.LastSent.IsZero() || !state.ReservedAt.IsZero() || state.Token != "") {
		return state, nil
	}
	var legacy time.Time
	if err := json.Unmarshal(data, &legacy); err != nil {
		return vacationReplyState{}, err
	}
	return vacationReplyState{LastSent: legacy}, nil
}

// ReserveVacationReply atomically claims the right to enqueue one automatic
// reply. Reservations expire after a short lease so a crash before enqueueing
// cannot suppress replies for the full rate-limit interval.
func (us *UserStore) ReserveVacationReply(ctx context.Context, userID, sender string) (string, bool, error) {
	return us.ReserveVacationReplyWithin(ctx, userID, sender, 24*time.Hour)
}

// ReserveVacationReplyWithin is ReserveVacationReply with the suppression
// period chosen by the caller: a Sieve vacation :days or :seconds value. The
// key may be a sender address or a Sieve response-tracking key that also
// names the vacation handle.
func (us *UserStore) ReserveVacationReplyWithin(ctx context.Context, userID, sender string, period time.Duration) (string, bool, error) {
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", false, err
	}
	token, key, now := hex.EncodeToString(tokenBytes), vacationReplyKey(userID, sender), time.Now().UTC()
	reserved := false
	err := store.Batch(ctx, us.ts.Store(), func(batchCtx context.Context) error {
		state, err := us.vacationReplyState(batchCtx, key)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if !state.LastSent.IsZero() && now.Sub(state.LastSent) < period {
			return nil
		}
		if state.Token != "" && now.Sub(state.ReservedAt) < vacationReservationLease {
			return nil
		}
		state.ReservedAt, state.Token = now, token
		if err := us.ts.Set(batchCtx, NSVacationReplies, key, state); err != nil {
			return err
		}
		reserved = true
		return nil
	})
	return token, reserved, err
}

func (us *UserStore) CompleteVacationReply(ctx context.Context, userID, sender, token string) error {
	return us.finishVacationReservation(ctx, userID, sender, token, true)
}

func (us *UserStore) CancelVacationReply(ctx context.Context, userID, sender, token string) error {
	return us.finishVacationReservation(ctx, userID, sender, token, false)
}

func (us *UserStore) finishVacationReservation(ctx context.Context, userID, sender, token string, sent bool) error {
	key := vacationReplyKey(userID, sender)
	return store.Batch(ctx, us.ts.Store(), func(batchCtx context.Context) error {
		state, err := us.vacationReplyState(batchCtx, key)
		if err != nil {
			return err
		}
		if token == "" || state.Token != token {
			return store.ErrPreconditionFailed
		}
		if sent {
			return us.ts.Set(batchCtx, NSVacationReplies, key, time.Now().UTC())
		}
		if state.LastSent.IsZero() {
			return us.ts.Delete(batchCtx, NSVacationReplies, key)
		}
		return us.ts.Set(batchCtx, NSVacationReplies, key, state.LastSent)
	})
}

// ShouldVacationReply returns true if a vacation reply should be sent to this sender
// (i.e., it's been more than 24h since the last reply).
func (us *UserStore) ShouldVacationReply(ctx context.Context, userID, sender string) bool {
	t, err := us.LastVacationReply(ctx, userID, sender)
	if err != nil {
		return true // No record means we should reply
	}
	return time.Since(t) >= 24*time.Hour
}

// GetQuota returns the quota info for a user.
func (us *UserStore) GetQuota(ctx context.Context, id string) (QuotaInfo, error) {
	u, err := us.Get(ctx, normalizeID(id))
	if err != nil {
		return QuotaInfo{}, err
	}
	return QuotaInfo{
		MaxStorageBytes:     u.MaxStorageBytes,
		MaxItems:            u.MaxItems,
		CurrentStorageBytes: u.CurrentStorageBytes,
		CurrentItems:        u.CurrentItems,
	}, nil
}

// UpdateQuota updates the quota limits for a user.
func (us *UserStore) UpdateQuota(ctx context.Context, id string, maxStorageBytes int64, maxItems int) error {
	return us.Update(ctx, normalizeID(id), func(u *User) {
		u.MaxStorageBytes = maxStorageBytes
		u.MaxItems = maxItems
	})
}

// IncrementUsage atomically increments the usage counters for a user.
// Returns ErrQuotaExceeded if the new item would exceed the quota.
func (us *UserStore) IncrementUsage(ctx context.Context, id string, size int64) error {
	return us.AdjustUsage(ctx, id, size, 1)
}

// DecrementUsage decrements the usage counters for a user.
func (us *UserStore) DecrementUsage(ctx context.Context, id string, size int64) error {
	return us.AdjustUsage(ctx, id, -size, -1)
}

// CheckAndIncrementUsage checks quota and increments usage counters.
// This is the preferred method for ItemStore.Append to use.
// Returns ErrQuotaExceeded if the operation would exceed the quota.
func (us *UserStore) CheckAndIncrementUsage(ctx context.Context, id string, size int64) error {
	return us.AdjustUsage(ctx, id, size, 1)
}

// AdjustUsage changes both quota counters in the caller's transaction. Positive
// deltas are checked before either counter is committed; negative deltas clamp
// at zero so repair and deletion cannot underflow corrupted legacy counters.
func (us *UserStore) AdjustUsage(ctx context.Context, id string, storageDelta int64, itemDelta int) error {
	return store.Batch(ctx, us.ts.Store(), func(batchCtx context.Context) error {
		return us.adjustUsage(batchCtx, id, storageDelta, itemDelta)
	})
}

func (us *UserStore) adjustUsage(ctx context.Context, id string, storageDelta int64, itemDelta int) error {
	var exceeded bool
	err := us.Update(ctx, normalizeID(id), func(u *User) {
		storage := max(int64(0), u.CurrentStorageBytes+storageDelta)
		items := max(0, u.CurrentItems+itemDelta)
		if !quotaExempt(ctx) && ((u.MaxStorageBytes > 0 && storage > u.MaxStorageBytes) || (u.MaxItems > 0 && items > u.MaxItems)) {
			exceeded = true
			return
		}
		u.CurrentStorageBytes = storage
		u.CurrentItems = items
	})
	if exceeded {
		return ErrQuotaExceeded
	}
	return err
}

// ListAllEmailAddresses returns all email addresses across all users.
func (us *UserStore) ListAllEmailAddresses(ctx context.Context) ([]EmailAddress, error) {
	keys, err := us.ts.List(ctx, NSEmails)
	if err != nil {
		return nil, err
	}
	var result []EmailAddress
	seen := make(map[string]bool)
	for _, k := range keys {
		// Only read addr: keys (skip user: and domain: index keys)
		if !strings.HasPrefix(k, "addr:") {
			continue
		}
		addr := strings.TrimPrefix(k, "addr:")
		if seen[addr] {
			continue
		}
		seen[addr] = true
		ea, err := us.GetEmailAddress(ctx, addr)
		if err != nil {
			continue
		}
		result = append(result, ea)
	}
	return result, nil
}

// --- OAuth2 Client CRUD ---

// CreateOAuth2Client creates a new OAuth2 client for a user.
func (us *UserStore) CreateOAuth2Client(ctx context.Context, userID, clientID, clientSecret string,
	redirectURIs, scopes []string, tokenURL string) (*OAuth2Client, error) {
	// Hash the client secret with bcrypt
	secretHash, err := auth.HashPassword(clientSecret)
	if err != nil {
		return nil, err
	}

	// Generate a unique ID
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	clientID_ := hex.EncodeToString(idBytes)

	client := &OAuth2Client{
		ID:           clientID_,
		UserID:       normalizeID(userID),
		ClientID:     clientID,
		ClientSecret: secretHash,
		RedirectURIs: redirectURIs,
		TokenURL:     tokenURL,
		Scopes:       scopes,
		CreatedAt:    time.Now().UTC(),
	}

	if err := us.oauthClients.put(ctx, client.ID, *client); err != nil {
		return nil, err
	}

	return client, nil
}

// GetOAuth2Client returns an OAuth2 client by its ID.
func (us *UserStore) GetOAuth2Client(ctx context.Context, id string) (*OAuth2Client, error) {
	client, err := us.oauthClients.get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &client, nil
}

// GetOAuth2ClientByClientID returns an OAuth2 client by its client_id.
func (us *UserStore) GetOAuth2ClientByClientID(ctx context.Context, clientID string) (*OAuth2Client, error) {
	_, client, err := us.oauthClients.find(ctx, func(client OAuth2Client) bool {
		return client.ClientID == clientID
	})
	if err != nil {
		return nil, err
	}
	return &client, nil
}

// ListOAuth2Clients returns all OAuth2 clients for a user.
func (us *UserStore) ListOAuth2Clients(ctx context.Context, userID string) ([]OAuth2Client, error) {
	return us.oauthClients.filter(ctx, func(client OAuth2Client) bool {
		return client.UserID == normalizeID(userID)
	})
}

// DeleteOAuth2Client removes an OAuth2 client.
func (us *UserStore) DeleteOAuth2Client(ctx context.Context, id string) error {
	return us.oauthClients.delete(ctx, id)
}

// --- OAuth2 Token CRUD ---

// StoreOAuth2Token stores or updates an OAuth2 token for a user and provider.
func (us *UserStore) StoreOAuth2Token(ctx context.Context, userID, provider, accessToken, refreshToken string,
	expiresAt time.Time, scopes []string) error {
	token := OAuth2Token{
		UserID:       normalizeID(userID),
		Provider:     provider,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		Scopes:       scopes,
		CreatedAt:    time.Now().UTC(),
	}
	key := userID + ":" + provider
	return us.ts.Set(ctx, NSOAuth2Tokens, key, token)
}

// GetOAuth2Token returns the OAuth2 token for a user and provider.
func (us *UserStore) GetOAuth2Token(ctx context.Context, userID, provider string) (*OAuth2Token, error) {
	var token OAuth2Token
	key := normalizeID(userID) + ":" + provider
	if err := us.ts.Get(ctx, NSOAuth2Tokens, key, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

// DeleteOAuth2Token removes an OAuth2 token for a user and provider.
func (us *UserStore) DeleteOAuth2Token(ctx context.Context, userID, provider string) error {
	key := normalizeID(userID) + ":" + provider
	return us.ts.Delete(ctx, NSOAuth2Tokens, key)
}

// --- Password Reset ---

// PasswordResetTTL is the default time-to-live for password reset tokens.
const PasswordResetTTL = 1 * time.Hour

func matchResetToken(token string) func(PasswordResetToken) bool {
	return func(prt PasswordResetToken) bool { return prt.Token == token }
}

// GeneratePasswordResetToken creates a random 32-byte hex token for a user,
// stores it with a 1h TTL, and returns the plain token string.
func (us *UserStore) GeneratePasswordResetToken(ctx context.Context, userID string) (string, error) {
	userID = normalizeID(userID)

	// Verify the user exists
	if _, err := us.Get(ctx, userID); err != nil {
		return "", err
	}

	// Generate random 32-byte hex token
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)

	prt := PasswordResetToken{
		UserID:    userID,
		Token:     token,
		ExpiresAt: time.Now().UTC().Add(PasswordResetTTL),
		Used:      false,
		CreatedAt: time.Now().UTC(),
	}

	key := PasswordResetKey(userID, token[:8])
	if err := us.resets.put(ctx, key, prt); err != nil {
		return "", err
	}

	return token, nil
}

// ValidatePasswordResetToken checks that a token exists, is not expired, and is not used.
// Returns the target UserID if valid.
func (us *UserStore) ValidatePasswordResetToken(ctx context.Context, token string) (string, error) {
	_, prt, err := us.resets.find(ctx, matchResetToken(token))
	if err != nil {
		return "", err
	}
	if prt.Used || time.Now().UTC().After(prt.ExpiresAt) {
		return "", store.ErrNotFound
	}
	return prt.UserID, nil
}

// CompletePasswordReset validates the token, hashes the new password,
// updates the user, and marks the token as used.
func (us *UserStore) CompletePasswordReset(ctx context.Context, token, newPassword string) error {
	userID, err := us.ValidatePasswordResetToken(ctx, token)
	if err != nil {
		return err
	}

	// Hash the new password
	passwordHash, err := auth.HashPassword(newPassword)
	if err != nil {
		return err
	}

	// Update the user's password
	if err := us.Update(ctx, userID, func(u *User) {
		u.PasswordHash = passwordHash
	}); err != nil {
		return err
	}

	// Mark the token as used
	key, prt, err := us.resets.find(ctx, matchResetToken(token))
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	prt.Used = true
	prt.UsedAt = time.Now().UTC()
	return us.resets.set(ctx, key, prt)
}

// CleanupExpiredResetTokens removes expired and used tokens older than 24h.
func (us *UserStore) CleanupExpiredResetTokens(ctx context.Context) int {
	now := time.Now().UTC()
	removed := 0
	_ = us.resets.scan(ctx, func(key string, prt PasswordResetToken) bool {
		// Remove if expired or if used and older than 24h
		if now.After(prt.ExpiresAt) || (prt.Used && now.Sub(prt.UsedAt) > 24*time.Hour) {
			if err := us.resets.delete(ctx, key); err == nil {
				removed++
			}
		}
		return true
	})
	return removed
}

// ListPasswordResetTokens returns all pending (unused, unexpired) password reset tokens.
func (us *UserStore) ListPasswordResetTokens(ctx context.Context) ([]PasswordResetToken, error) {
	now := time.Now().UTC()
	return us.resets.filter(ctx, func(prt PasswordResetToken) bool {
		return !prt.Used && now.Before(prt.ExpiresAt)
	})
}

// RevokePasswordResetToken marks a specific token as used (revoked).
func (us *UserStore) RevokePasswordResetToken(ctx context.Context, token string) error {
	key, prt, err := us.resets.find(ctx, matchResetToken(token))
	if err != nil {
		return err
	}
	if prt.Used {
		return store.ErrNotFound
	}
	prt.Used = true
	prt.UsedAt = time.Now().UTC()
	return us.resets.set(ctx, key, prt)
}

// UpdateSpamConfig updates the user's spam filtering configuration. A zero
// threshold uses the server's junk threshold.
func (us *UserStore) UpdateSpamConfig(ctx context.Context, id string, enabled bool, threshold float64) error {
	return us.Update(ctx, id, func(u *User) {
		u.SpamEnabled = enabled
		u.SpamThreshold = threshold
	})
}

// GetSpamConfig returns whether the account files spam in Junk and at
// which score; zero means the server's junk threshold applies.
func (us *UserStore) GetSpamConfig(ctx context.Context, id string) (enabled bool, threshold float64, err error) {
	u, err := us.Get(ctx, id)
	if err != nil {
		return false, 0, err
	}
	return u.SpamEnabled, u.SpamThreshold, nil
}

// --- Spam Whitelist/Blacklist ---

// SpamListKind identifies one personal sender-policy list.
type SpamListKind string

const (
	SpamListAllow SpamListKind = "allow"
	SpamListBlock SpamListKind = "block"
)

// SpamListEntry is one durable personal sender policy. A zero ExpiresAt keeps
// the entry until the account owner removes or replaces it.
type SpamListEntry struct {
	Value     string    `json:"value"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

// SpamWhitelistKey builds the metadata key for a user's spam whitelist.
func SpamWhitelistKey(userID string) string { return "spam_whitelist:" + normalizeID(userID) }

// SpamBlacklistKey builds the metadata key for a user's spam blacklist.
func SpamBlacklistKey(userID string) string { return "spam_blacklist:" + normalizeID(userID) }

// SpamListExpirationsKey stores optional expiries separately so existing
// string-list data and consumers remain backward compatible.
func SpamListExpirationsKey(userID string, kind SpamListKind) string {
	return "spam_" + string(kind) + "_expirations:" + normalizeID(userID)
}

// GetSpamWhitelist returns the list of whitelisted senders for a user.
func (us *UserStore) GetSpamWhitelist(ctx context.Context, id string) []string {
	list, err := us.ReadSpamWhitelist(ctx, id)
	if err != nil {
		return nil
	}
	return list
}

// ReadSpamWhitelist is the error-preserving form used by delivery policy.
func (us *UserStore) ReadSpamWhitelist(ctx context.Context, id string) ([]string, error) {
	entries, err := us.ReadSpamListEntries(ctx, id, SpamListAllow)
	if err != nil {
		return nil, err
	}
	return spamListValues(entries), nil
}

// SetSpamWhitelist sets the list of whitelisted senders for a user.
func (us *UserStore) SetSpamWhitelist(ctx context.Context, id string, entries []string) error {
	return us.setPermanentSpamList(ctx, id, SpamListAllow, entries)
}

// AddSpamWhitelist adds a sender to the user's spam whitelist.
func (us *UserStore) AddSpamWhitelist(ctx context.Context, id string, entry string) error {
	return us.AddSpamListEntry(ctx, id, SpamListAllow, entry, time.Time{})
}

// RemoveSpamWhitelist removes a sender from the user's spam whitelist.
func (us *UserStore) RemoveSpamWhitelist(ctx context.Context, id string, entry string) error {
	return us.RemoveSpamListEntry(ctx, id, SpamListAllow, entry)
}

// GetSpamBlacklist returns the list of blacklisted senders for a user.
func (us *UserStore) GetSpamBlacklist(ctx context.Context, id string) []string {
	list, err := us.ReadSpamBlacklist(ctx, id)
	if err != nil {
		return nil
	}
	return list
}

// ReadSpamBlacklist is the error-preserving form used by delivery policy.
func (us *UserStore) ReadSpamBlacklist(ctx context.Context, id string) ([]string, error) {
	entries, err := us.ReadSpamListEntries(ctx, id, SpamListBlock)
	if err != nil {
		return nil, err
	}
	return spamListValues(entries), nil
}

// SetSpamBlacklist sets the list of blacklisted senders for a user.
func (us *UserStore) SetSpamBlacklist(ctx context.Context, id string, entries []string) error {
	return us.setPermanentSpamList(ctx, id, SpamListBlock, entries)
}

// AddSpamBlacklist adds a sender to the user's spam blacklist.
func (us *UserStore) AddSpamBlacklist(ctx context.Context, id string, entry string) error {
	return us.AddSpamListEntry(ctx, id, SpamListBlock, entry, time.Time{})
}

// RemoveSpamBlacklist removes a sender from the user's spam blacklist.
func (us *UserStore) RemoveSpamBlacklist(ctx context.Context, id string, entry string) error {
	return us.RemoveSpamListEntry(ctx, id, SpamListBlock, entry)
}

// ReadSpamListEntries returns active entries and atomically prunes expired
// values. Delivery callers therefore never enforce a stale allow or block.
func (us *UserStore) ReadSpamListEntries(ctx context.Context, id string, kind SpamListKind) ([]SpamListEntry, error) {
	var result []SpamListEntry
	err := store.Batch(ctx, us.ts.Store(), func(batchCtx context.Context) error {
		entries, changed, err := us.readSpamListEntries(batchCtx, id, kind, time.Now().UTC())
		if err != nil {
			return err
		}
		if changed {
			if err := us.writeSpamListEntries(batchCtx, id, kind, entries); err != nil {
				return err
			}
		}
		result = entries
		return nil
	})
	return result, err
}

// AddSpamListEntry adds or replaces one entry and removes the same value from
// the opposite list in the same durable batch.
func (us *UserStore) AddSpamListEntry(ctx context.Context, id string, kind SpamListKind, value string, expiresAt time.Time) error {
	if !validSpamListKind(kind) {
		return errors.New("invalid spam list kind")
	}
	if !expiresAt.IsZero() {
		expiresAt = expiresAt.UTC()
		if !expiresAt.After(time.Now().UTC()) {
			return errors.New("spam list expiry must be in the future")
		}
	}
	return store.Batch(ctx, us.ts.Store(), func(batchCtx context.Context) error {
		now := time.Now().UTC()
		selected, _, err := us.readSpamListEntries(batchCtx, id, kind, now)
		if err != nil {
			return err
		}
		selected = upsertSpamListEntry(selected, SpamListEntry{Value: value, ExpiresAt: expiresAt})
		if err := us.writeSpamListEntries(batchCtx, id, kind, selected); err != nil {
			return err
		}
		opposite := SpamListAllow
		if kind == SpamListAllow {
			opposite = SpamListBlock
		}
		other, _, err := us.readSpamListEntries(batchCtx, id, opposite, now)
		if err != nil {
			return err
		}
		return us.writeSpamListEntries(batchCtx, id, opposite, removeSpamListValue(other, value))
	})
}

// RemoveSpamListEntry removes both the value and its optional expiry.
func (us *UserStore) RemoveSpamListEntry(ctx context.Context, id string, kind SpamListKind, value string) error {
	if !validSpamListKind(kind) {
		return errors.New("invalid spam list kind")
	}
	return store.Batch(ctx, us.ts.Store(), func(batchCtx context.Context) error {
		entries, _, err := us.readSpamListEntries(batchCtx, id, kind, time.Now().UTC())
		if err != nil {
			return err
		}
		return us.writeSpamListEntries(batchCtx, id, kind, removeSpamListValue(entries, value))
	})
}

func (us *UserStore) setPermanentSpamList(ctx context.Context, id string, kind SpamListKind, values []string) error {
	if !validSpamListKind(kind) {
		return errors.New("invalid spam list kind")
	}
	entries := make([]SpamListEntry, 0, len(values))
	for _, value := range values {
		entries = append(entries, SpamListEntry{Value: value})
	}
	return store.Batch(ctx, us.ts.Store(), func(batchCtx context.Context) error {
		return us.writeSpamListEntries(batchCtx, id, kind, entries)
	})
}

func (us *UserStore) readSpamListEntries(ctx context.Context, id string, kind SpamListKind, now time.Time) ([]SpamListEntry, bool, error) {
	if !validSpamListKind(kind) {
		return nil, false, errors.New("invalid spam list kind")
	}
	values, err := us.ts.StringList(ctx, NSMetadata, spamListKey(id, kind))
	if errors.Is(err, store.ErrNotFound) {
		values = []string{}
	} else if err != nil {
		return nil, false, err
	}
	expirations := map[string]time.Time{}
	if err := us.ts.Get(ctx, NSMetadata, SpamListExpirationsKey(id, kind), &expirations); err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, false, err
	}
	entries := make([]SpamListEntry, 0, len(values))
	changed := false
	for _, value := range values {
		expiresAt := expirations[value]
		if !expiresAt.IsZero() && !expiresAt.After(now) {
			changed = true
			continue
		}
		entries = append(entries, SpamListEntry{Value: value, ExpiresAt: expiresAt})
		if !expiresAt.IsZero() {
			delete(expirations, value)
		}
	}
	return entries, changed || len(expirations) > 0, nil
}

func (us *UserStore) writeSpamListEntries(ctx context.Context, id string, kind SpamListKind, entries []SpamListEntry) error {
	values := make([]string, 0, len(entries))
	expirations := make(map[string]time.Time)
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if _, exists := seen[entry.Value]; exists {
			continue
		}
		seen[entry.Value] = struct{}{}
		values = append(values, entry.Value)
		if !entry.ExpiresAt.IsZero() {
			expirations[entry.Value] = entry.ExpiresAt.UTC()
		}
	}
	if err := us.ts.SetStringList(ctx, NSMetadata, spamListKey(id, kind), values); err != nil {
		return err
	}
	return us.ts.Set(ctx, NSMetadata, SpamListExpirationsKey(id, kind), expirations)
}

func spamListKey(id string, kind SpamListKind) string {
	if kind == SpamListAllow {
		return SpamWhitelistKey(id)
	}
	return SpamBlacklistKey(id)
}

func validSpamListKind(kind SpamListKind) bool { return kind == SpamListAllow || kind == SpamListBlock }

func spamListValues(entries []SpamListEntry) []string {
	values := make([]string, 0, len(entries))
	for _, entry := range entries {
		values = append(values, entry.Value)
	}
	return values
}

func upsertSpamListEntry(entries []SpamListEntry, replacement SpamListEntry) []SpamListEntry {
	for index := range entries {
		if entries[index].Value == replacement.Value {
			entries[index] = replacement
			return entries
		}
	}
	return append(entries, replacement)
}

func removeSpamListValue(entries []SpamListEntry, value string) []SpamListEntry {
	filtered := make([]SpamListEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.Value != value {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}
