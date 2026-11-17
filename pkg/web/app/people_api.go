package app

import (
	"context"
	"errors"
	"github.com/lkarlslund/veksel/pkg/calendarindex"
	"net/http"
	"net/mail"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	calendarcore "github.com/lkarlslund/veksel/pkg/calendar"
	"github.com/lkarlslund/veksel/pkg/model"
	"github.com/lkarlslund/veksel/pkg/service"
	"github.com/lkarlslund/veksel/pkg/store"
)

// People surfaces (contact cards, ranked recipient suggestions, favorites,
// and global search suggestions) only combine data the caller can already
// read: contact folders through search and FolderSpace authorization in the
// current acting context, and the directory of enabled identities in the
// subject's own mail domains.

const (
	maxPeopleSuggestions     = 25
	maxPeopleContactFolders  = 1024
	maxCardRecentMessages    = 5
	maxCardUpcoming          = 5
	maxCardCalendars         = 25
	cardUpcomingWindow       = 60 * 24 * time.Hour
	maxSearchSuggestionQuery = 200
	maxSearchSuggestions     = 10
	maxDirectoryPerDomain    = 5000
	maxGroupScanItems        = 5000
	directoryCacheTTL        = time.Minute
)

// visibleContactHit is one authorized contact search hit with its folder.
type visibleContactHit struct {
	service.SearchHit
	Folder model.Folder
}

func (hit visibleContactHit) addresses() []*mail.Address {
	result := make([]*mail.Address, 0, len(hit.ContactEmails))
	for _, value := range hit.ContactEmails {
		address, err := mail.ParseAddress(strings.TrimSpace(value))
		if err == nil && address.Address != "" {
			result = append(result, address)
		}
	}
	return result
}

func (hit visibleContactHit) recentRecipient() bool {
	return hit.Folder.SpecialUse == model.SpecialUseRecentRecipients
}

// searchVisibleContacts runs the contact suggestion query once per address
// book owner across every RBAC-visible contact folder, the subject's own
// first. ownOnly limits it to the subject's address books. Owners whose
// account search is forbidden are skipped; an index that cannot answer for
// any owner reports ErrSearchUnavailable.
func (h *Handler) searchVisibleContacts(r *http.Request, query string, limit int, ownOnly bool) ([]visibleContactHit, error) {
	if h.search == nil {
		return nil, service.ErrSearchUnavailable
	}
	folders, err := h.workspace.ListFolders(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r))
	if err != nil {
		return nil, err
	}
	subjectID := strings.ToLower(currentSubject(r).ID)
	folderByID := make(map[string]model.Folder)
	foldersByOwner := make(map[string][]string)
	for _, folder := range folders {
		if folder.Type != model.FolderTypeContacts || len(foldersByOwner[folder.UserID]) >= maxPeopleContactFolders || ownOnly && !strings.EqualFold(folder.UserID, subjectID) {
			continue
		}
		folderByID[folder.ID] = folder
		foldersByOwner[folder.UserID] = append(foldersByOwner[folder.UserID], folder.ID)
	}
	owners := make([]string, 0, len(foldersByOwner))
	for owner := range foldersByOwner {
		owners = append(owners, owner)
	}
	sort.Slice(owners, func(i, j int) bool {
		if strings.EqualFold(owners[i], subjectID) != strings.EqualFold(owners[j], subjectID) {
			return strings.EqualFold(owners[i], subjectID)
		}
		return owners[i] < owners[j]
	})
	access := webAccess(currentActor(r), currentSubject(r), currentActingMode(r))
	var hits []visibleContactHit
	var unavailable error
	searched := false
	for _, owner := range owners {
		page, searchErr := h.search.Search(r.Context(), access, service.SearchQuery{
			AccountID: owner, FolderIDs: foldersByOwner[owner], Types: []model.FolderType{model.FolderTypeContacts},
			Filter: &service.SearchFilter{Operator: service.SearchContains, Field: "contact_suggest", Value: query},
			Sort:   "contact_name", Limit: limit,
		})
		if errors.Is(searchErr, service.ErrForbidden) {
			continue
		}
		if errors.Is(searchErr, service.ErrSearchUnavailable) {
			unavailable = searchErr
			continue
		}
		if searchErr != nil {
			return nil, searchErr
		}
		searched = true
		for _, hit := range page.Hits {
			folder, visible := folderByID[hit.FolderID]
			if visible && strings.EqualFold(folder.UserID, owner) {
				hits = append(hits, visibleContactHit{SearchHit: hit, Folder: folder})
			}
		}
	}
	if !searched && unavailable != nil {
		return nil, unavailable
	}
	return hits, nil
}

// mailDomains returns the domains of userID's enabled identities.
func (h *Handler) mailDomains(ctx context.Context, userID string) (map[string]bool, error) {
	identities, err := h.users.ListEmailAddressesForUser(ctx, userID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	domains := make(map[string]bool, len(identities))
	for _, identity := range identities {
		if identity.Enabled {
			domains[strings.ToLower(identity.DomainID)] = true
		}
	}
	return domains, nil
}

type directoryPerson struct {
	Name   string
	Email  string
	UserID string
}

type directoryDomainEntry struct {
	loaded time.Time
	people []directoryPerson
}

// peopleDirectoryCache keeps each domain's enabled identities briefly so
// typing in a recipient field does not rescan the domain on every keystroke.
type peopleDirectoryCache struct {
	mu      sync.Mutex
	domains map[string]directoryDomainEntry
}

// directoryPeople returns the enabled identities of enabled accounts in the
// subject's own mail domains.
func (h *Handler) directoryPeople(ctx context.Context, subject string) ([]directoryPerson, error) {
	domains, err := h.mailDomains(ctx, subject)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(domains))
	for domain := range domains {
		names = append(names, domain)
	}
	sort.Strings(names)
	var people []directoryPerson
	for _, domain := range names {
		entries, err := h.directoryDomain(ctx, domain)
		if err != nil {
			return nil, err
		}
		people = append(people, entries...)
	}
	return people, nil
}

func (h *Handler) directoryDomain(ctx context.Context, domain string) ([]directoryPerson, error) {
	cache := &h.peopleDirectory
	cache.mu.Lock()
	entry, found := cache.domains[domain]
	cache.mu.Unlock()
	if found && time.Since(entry.loaded) < directoryCacheTTL {
		return entry.people, nil
	}
	identities, err := h.users.ListEmailAddressesForDomain(ctx, domain)
	if err != nil {
		return nil, err
	}
	people := make([]directoryPerson, 0, min(len(identities), maxDirectoryPerDomain))
	accounts := make(map[string]model.User)
	for _, identity := range identities {
		if len(people) >= maxDirectoryPerDomain {
			break
		}
		if !identity.Enabled || identity.UserID == "" {
			continue
		}
		user, known := accounts[identity.UserID]
		if !known {
			user, err = h.users.Get(ctx, identity.UserID)
			if err != nil {
				continue
			}
			accounts[identity.UserID] = user
		}
		if !user.Enabled {
			continue
		}
		people = append(people, directoryPerson{Name: strings.TrimSpace(user.DisplayName), Email: strings.ToLower(identity.ID), UserID: user.ID})
	}
	cache.mu.Lock()
	if cache.domains == nil {
		cache.domains = make(map[string]directoryDomainEntry)
	}
	cache.domains[domain] = directoryDomainEntry{loaded: time.Now(), people: people}
	cache.mu.Unlock()
	return people, nil
}

// peopleMatch reports whether every query word prefixes a word of the name
// or the address, mirroring the contact suggestion index.
func peopleMatch(query, name, email string) bool {
	words := contactWords(name + " " + email)
	for _, token := range contactWords(query) {
		if !slices.ContainsFunc(words, func(word string) bool { return strings.HasPrefix(word, token) }) {
			return false
		}
	}
	return true
}

func contactWords(value string) []string {
	return strings.FieldsFunc(strings.ToLower(value), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsNumber(r) })
}

type peopleSuggestion struct {
	Kind        string    `json:"kind"`
	Name        string    `json:"name"`
	Email       string    `json:"email,omitempty"`
	Source      string    `json:"source"`
	Favorite    bool      `json:"favorite,omitempty"`
	ItemID      string    `json:"item_id,omitempty"`
	FolderID    string    `json:"folder_id,omitempty"`
	Addressbook string    `json:"addressbook,omitempty"`
	PhotoURL    string    `json:"photo_url,omitempty"`
	MemberCount int       `json:"member_count,omitempty"`
	Uses        int       `json:"uses,omitempty"`
	LastUsed    time.Time `json:"last_used,omitzero"`
	Score       int       `json:"score"`
}

// peopleScore ranks favorites first, then match quality, source, how often
// and how recently the subject wrote to the address.
func peopleScore(suggestion peopleSuggestion, query string, now time.Time) int {
	score := []int{60, 40, 30, 10}[suggestionRank(contactSuggestion{Name: suggestion.Name, Email: suggestion.Email}, query)]
	if suggestion.Favorite {
		score += 1000
	}
	score += map[string]int{"contact": 30, "directory": 20}[suggestion.Source]
	score += min(suggestion.Uses, 50) * 4
	if !suggestion.LastUsed.IsZero() {
		switch age := now.Sub(suggestion.LastUsed); {
		case age < 7*24*time.Hour:
			score += 40
		case age < 30*24*time.Hour:
			score += 25
		case age < 180*24*time.Hour:
			score += 10
		}
	}
	return score
}

func (h *Handler) favoriteContacts(r *http.Request) map[string]bool {
	user, err := h.users.Get(r.Context(), currentActor(r).ID)
	if err != nil {
		return nil
	}
	favorites := make(map[string]bool, len(user.FavoriteContacts))
	for _, id := range user.FavoriteContacts {
		favorites[id] = true
	}
	return favorites
}

// rankedPeople merges visible contacts, contact groups, recent recipients,
// and same-domain directory entries into one ranked list. An empty query
// returns the caller's favorites.
func (h *Handler) rankedPeople(r *http.Request, query string, limit int) ([]peopleSuggestion, error) {
	query = strings.ToLower(strings.TrimSpace(query))
	favorites := h.favoriteContacts(r)
	if query == "" {
		favorites, err := h.favoriteSummaries(r)
		if err != nil {
			return nil, err
		}
		result := make([]peopleSuggestion, 0, min(len(favorites), limit))
		for _, favorite := range favorites {
			if len(result) >= limit {
				break
			}
			kind := "person"
			if favorite.Kind == "group" {
				kind = "group"
			} else if favorite.Email == "" {
				continue
			}
			result = append(result, peopleSuggestion{Kind: kind, Name: favorite.FN, Email: favorite.Email, Source: "contact", Favorite: true, ItemID: favorite.ID, FolderID: favorite.FolderID, Addressbook: favorite.Addressbook, PhotoURL: favorite.PhotoURL, MemberCount: favorite.MemberCount, Score: 1000})
		}
		return result, nil
	}
	hits, err := h.searchVisibleContacts(r, query, min(limit*2, 50), false)
	if err != nil && !errors.Is(err, service.ErrSearchUnavailable) {
		return nil, err
	}
	searchErr := err
	byEmail := make(map[string]*peopleSuggestion)
	var ordered []*peopleSuggestion
	merge := func(candidate peopleSuggestion) {
		existing := byEmail[candidate.Email]
		if existing == nil {
			entry := candidate
			byEmail[candidate.Email] = &entry
			ordered = append(ordered, &entry)
			return
		}
		existing.Uses += candidate.Uses
		if candidate.LastUsed.After(existing.LastUsed) {
			existing.LastUsed = candidate.LastUsed
		}
		existing.Favorite = existing.Favorite || candidate.Favorite
		if existing.PhotoURL == "" {
			existing.PhotoURL = candidate.PhotoURL
		}
		// A real contact or directory entry outranks the recipient
		// history's derived name and identity.
		if existing.Source == "recent" && candidate.Source != "recent" || existing.Source == "directory" && candidate.Source == "contact" {
			uses, last, favorite, photo := existing.Uses, existing.LastUsed, existing.Favorite, existing.PhotoURL
			*existing = candidate
			existing.Uses, existing.LastUsed, existing.Favorite = uses, last, favorite
			if existing.PhotoURL == "" {
				existing.PhotoURL = photo
			}
		}
	}
	var groups []peopleSuggestion
	for _, hit := range hits {
		if strings.EqualFold(hit.ContactKind, "group") {
			groups = append(groups, peopleSuggestion{Kind: "group", Name: hit.Name, Source: "contact", Favorite: favorites[hit.ItemID], ItemID: hit.ItemID, FolderID: hit.FolderID, Addressbook: hit.Folder.Name, MemberCount: hit.ContactMembers})
			continue
		}
		source, uses, lastUsed := "contact", 0, time.Time{}
		if hit.recentRecipient() {
			source = "recent"
			if item, itemErr := h.workspace.GetItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), hit.ItemID); itemErr == nil {
				uses, _ = strconv.Atoi(item.Headers["Use-Count"])
				lastUsed, _ = time.Parse(time.RFC3339Nano, item.Headers["Last-Used"])
			}
		}
		for _, address := range hit.addresses() {
			name := strings.TrimSpace(hit.Name)
			if name == "" {
				name = strings.TrimSpace(address.Name)
			}
			suggestion := peopleSuggestion{Kind: "person", Name: name, Email: strings.ToLower(address.Address), Source: source, Favorite: favorites[hit.ItemID], Uses: uses, LastUsed: lastUsed, PhotoURL: contactSuggestionPhotoURL(hit.SearchHit)}
			if source == "contact" {
				suggestion.ItemID, suggestion.FolderID, suggestion.Addressbook = hit.ItemID, hit.FolderID, hit.Folder.Name
			}
			merge(suggestion)
		}
	}
	directory, err := h.directoryPeople(r.Context(), currentSubject(r).ID)
	if err != nil {
		return nil, err
	}
	matched := 0
	for _, person := range directory {
		if matched >= limit*2 {
			break
		}
		if peopleMatch(query, person.Name, person.Email) {
			matched++
			name := person.Name
			if name == "" {
				name = recipientName(person.Email)
			}
			merge(peopleSuggestion{Kind: "person", Name: name, Email: person.Email, Source: "directory", Addressbook: "Directory"})
		}
	}
	if len(ordered) == 0 && len(groups) == 0 && searchErr != nil && len(directory) == 0 {
		return nil, searchErr
	}
	now := time.Now()
	result := make([]peopleSuggestion, 0, len(ordered)+len(groups))
	for _, entry := range ordered {
		result = append(result, *entry)
	}
	result = append(result, groups...)
	for index := range result {
		result[index].Score = peopleScore(result[index], query, now)
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Score != result[j].Score {
			return result[i].Score > result[j].Score
		}
		if !strings.EqualFold(result[i].Name, result[j].Name) {
			return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name)
		}
		return result[i].Email < result[j].Email
	})
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func recipientName(email string) string {
	local, _, _ := strings.Cut(email, "@")
	if local == "" {
		return email
	}
	return local
}

func boundedLimit(r *http.Request, fallback, maximum int) int {
	if requested, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && requested > 0 {
		return min(requested, maximum)
	}
	return fallback
}

// apiPeopleSuggestions serves the ranked recipient autocomplete.
func (h *Handler) apiPeopleSuggestions(w http.ResponseWriter, r *http.Request) {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	if utf8.RuneCountInString(query) > maxSearchSuggestionQuery {
		jsonError(w, http.StatusBadRequest, "query is too long")
		return
	}
	suggestions, err := h.rankedPeople(r, query, boundedLimit(r, 12, maxPeopleSuggestions))
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, suggestions)
}

type groupMember struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email"`
}

// apiPeopleGroupMembers expands one readable contact group into member
// addresses. mailto: members are used directly; other URIs (normally
// urn:uuid:) resolve against contacts in the group's own address book.
func (h *Handler) apiPeopleGroupMembers(w http.ResponseWriter, r *http.Request) {
	item, err := h.workspace.GetItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), r.URL.Query().Get("item_id"))
	if err != nil {
		apiError(w, err)
		return
	}
	folder, err := h.workspaceFolder(r, item.FolderID, model.FolderTypeContacts)
	if err != nil {
		apiError(w, err)
		return
	}
	group := model.ParseVCard(item.Data)
	if !strings.EqualFold(group.Kind, "group") {
		jsonError(w, http.StatusBadRequest, "contact is not a group")
		return
	}
	var byUID map[string]model.Contact
	members := make([]groupMember, 0, len(group.Members))
	seen := make(map[string]bool)
	unresolved := 0
	add := func(name, email string) {
		email = strings.ToLower(strings.TrimSpace(email))
		if _, err := mail.ParseAddress(email); err != nil || seen[email] {
			return
		}
		seen[email] = true
		members = append(members, groupMember{Name: name, Email: email})
	}
	for _, member := range group.Members {
		if len(members) >= maxContactGroupMembers {
			break
		}
		if strings.HasPrefix(strings.ToLower(member), "mailto:") {
			add("", member[len("mailto:"):])
			continue
		}
		if byUID == nil {
			byUID, err = h.contactsByUID(r, folder.ID)
			if err != nil {
				apiError(w, err)
				return
			}
		}
		contact, found := byUID[member]
		if !found {
			contact, found = byUID[strings.TrimPrefix(member, "urn:uuid:")]
		}
		if !found || len(contact.Emails) == 0 || strings.EqualFold(contact.Kind, "group") {
			unresolved++
			continue
		}
		address, parseErr := mail.ParseAddress(contact.Emails[0])
		if parseErr != nil {
			unresolved++
			continue
		}
		add(contact.FN, address.Address)
	}
	jsonResponse(w, http.StatusOK, map[string]any{"item_id": item.ID, "name": group.FN, "members": members, "unresolved": unresolved})
}

// contactsByUID indexes one readable address book by vCard UID, bounded to
// maxGroupScanItems items.
func (h *Handler) contactsByUID(r *http.Request, folderID string) (map[string]model.Contact, error) {
	result := make(map[string]model.Contact)
	var before uint32
	for scanned := 0; scanned < maxGroupScanItems; {
		page, err := h.workspace.ListFullItemPage(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), folderID, before, 200)
		if err != nil {
			return nil, err
		}
		for _, item := range page.Items {
			contact := model.ParseVCard(item.Data)
			if contact.UID != "" {
				result[contact.UID] = contact
			}
		}
		scanned += len(page.Items)
		if page.NextBeforeUID == 0 || len(page.Items) == 0 {
			break
		}
		before = page.NextBeforeUID
	}
	return result, nil
}

type favoriteContact struct {
	workspaceContactSummary
	Addressbook string `json:"addressbook"`
	UserID      string `json:"user_id"`
	PhotoURL    string `json:"photo_url,omitempty"`
}

// favoriteSummaries resolves the actor's favorites that are still readable
// in the current acting context, in starring order.
func (h *Handler) favoriteSummaries(r *http.Request) ([]favoriteContact, error) {
	user, err := h.users.Get(r.Context(), currentActor(r).ID)
	if err != nil {
		return nil, err
	}
	if len(user.FavoriteContacts) == 0 {
		return []favoriteContact{}, nil
	}
	folders, err := h.workspace.ListFolders(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r))
	if err != nil {
		return nil, err
	}
	folderByID := make(map[string]model.Folder, len(folders))
	for _, folder := range folders {
		if folder.Type == model.FolderTypeContacts {
			folderByID[folder.ID] = folder
		}
	}
	result := make([]favoriteContact, 0, len(user.FavoriteContacts))
	for _, id := range user.FavoriteContacts {
		item, err := h.workspace.GetItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), id)
		if err != nil {
			continue
		}
		folder, visible := folderByID[item.FolderID]
		if !visible || !item.TrashedAt.IsZero() {
			continue
		}
		contact := model.ParseVCard(item.Data)
		summary := workspaceContactSummary{ID: item.ID, FolderID: folder.ID, FN: contact.FN, Kind: contact.Kind, MemberCount: len(contact.Members), Org: contact.Org}
		if len(contact.Emails) > 0 {
			if address, err := mail.ParseAddress(contact.Emails[0]); err == nil {
				summary.Email = strings.ToLower(address.Address)
			}
		}
		if len(contact.Phones) > 0 {
			summary.Phone = contact.Phones[0]
		}
		entry := favoriteContact{workspaceContactSummary: summary, Addressbook: folder.Name, UserID: folder.UserID}
		if len(contact.PhotoData) > 0 {
			entry.PhotoToken = contactPhotoVersion(item.UpdatedAt)
			entry.PhotoURL = contactSuggestionPhotoURL(service.SearchHit{ItemID: item.ID, ContactHasPhoto: true, Updated: item.UpdatedAt})
		}
		result = append(result, entry)
	}
	return result, nil
}

func (h *Handler) apiContactFavorites(w http.ResponseWriter, r *http.Request) {
	favorites, err := h.favoriteSummaries(r)
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"favorites": favorites, "maximum": model.MaxFavoriteContacts})
}

// apiSetContactFavorite stars (PUT) a readable contact or unstars (DELETE)
// any stored ID, so favorites of a no longer visible contact can be removed.
func (h *Handler) apiSetContactFavorite(w http.ResponseWriter, r *http.Request) {
	itemID := strings.TrimSpace(r.PathValue("id"))
	if itemID == "" {
		jsonError(w, http.StatusBadRequest, "contact is required")
		return
	}
	favorite := r.Method == http.MethodPut
	if favorite {
		item, err := h.workspace.GetItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), itemID)
		if err != nil {
			apiError(w, err)
			return
		}
		if _, err := h.workspaceFolder(r, item.FolderID, model.FolderTypeContacts); err != nil {
			apiError(w, err)
			return
		}
	}
	actor := currentActor(r).ID
	ids, err := h.users.SetContactFavorite(r.Context(), actor, itemID, favorite)
	if err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"favorite_ids": nonNilStrings(ids)})
}

type personCardContact struct {
	ItemID      string `json:"item_id"`
	FolderID    string `json:"folder_id"`
	Addressbook string `json:"addressbook"`
}

type personCardMessage struct {
	ItemID     string    `json:"item_id"`
	FolderID   string    `json:"folder_id"`
	FolderName string    `json:"folder_name"`
	Subject    string    `json:"subject"`
	Date       time.Time `json:"date,omitzero"`
	Unread     bool      `json:"unread,omitempty"`
}

type personCardMeeting struct {
	ID       string `json:"id"`
	FolderID string `json:"folder_id"`
	Summary  string `json:"summary"`
	Start    string `json:"start"`
	End      string `json:"end,omitempty"`
	AllDay   bool   `json:"all_day,omitempty"`
	Location string `json:"location,omitempty"`
}

type personCard struct {
	Email     string              `json:"email"`
	Name      string              `json:"name"`
	Title     string              `json:"title,omitempty"`
	Org       string              `json:"org,omitempty"`
	Emails    []string            `json:"emails"`
	Phones    []string            `json:"phones"`
	PhotoURL  string              `json:"photo_url,omitempty"`
	Contact   *personCardContact  `json:"contact,omitempty"`
	Favorite  bool                `json:"favorite,omitempty"`
	Directory bool                `json:"directory,omitempty"`
	Recent    []personCardMessage `json:"recent_messages"`
	Upcoming  []personCardMeeting `json:"upcoming_meetings"`
	// Partial lists the sections that could not be answered right now,
	// for example while the search index rebuilds.
	Partial []string `json:"partial,omitempty"`
}

// apiPersonCard describes one address for hover cards: the subject's own
// contact for it, a same-domain directory entry, the last messages from it,
// and upcoming meetings with it in the subject's own calendars.
func (h *Handler) apiPersonCard(w http.ResponseWriter, r *http.Request) {
	address, err := mail.ParseAddress(strings.TrimSpace(r.URL.Query().Get("email")))
	if err != nil || !strings.Contains(address.Address, "@") || len(address.Address) > 320 {
		jsonError(w, http.StatusBadRequest, "a valid email address is required")
		return
	}
	email := strings.ToLower(address.Address)
	card := personCard{Email: email, Emails: []string{email}, Phones: []string{}, Recent: []personCardMessage{}, Upcoming: []personCardMeeting{}}
	hint := strings.TrimSpace(r.URL.Query().Get("name"))
	if utf8.RuneCountInString(hint) > 200 {
		hint = ""
	}
	if err := h.cardContact(r, email, &card); err != nil {
		if !errors.Is(err, service.ErrSearchUnavailable) {
			apiError(w, err)
			return
		}
		card.Partial = append(card.Partial, "contact")
	}
	subject := currentSubject(r).ID
	if domains, err := h.mailDomains(r.Context(), subject); err == nil {
		_, domain, _ := strings.Cut(email, "@")
		if domains[domain] {
			if identity, err := h.users.GetEmailAddress(r.Context(), email); err == nil && identity.Enabled {
				if user, err := h.users.Get(r.Context(), identity.UserID); err == nil && user.Enabled {
					card.Directory = true
					if card.Name == "" {
						card.Name = strings.TrimSpace(user.DisplayName)
					}
				}
			}
		}
	}
	if card.Name == "" {
		card.Name = firstNonEmptyString(hint, strings.TrimSpace(address.Name), recipientName(email))
	}
	if err := h.cardRecentMessages(r, email, &card); err != nil {
		if !errors.Is(err, service.ErrSearchUnavailable) && !errors.Is(err, service.ErrForbidden) {
			apiError(w, err)
			return
		}
		card.Partial = append(card.Partial, "recent_messages")
	}
	if err := h.cardUpcomingMeetings(r, email, &card); err != nil {
		apiError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, card)
}

// cardContact fills card from the subject's own contact for email, preferring
// a real contact over the recipient history entry.
func (h *Handler) cardContact(r *http.Request, email string, card *personCard) error {
	// The suggestion index splits addresses differently from its query
	// tokenizer, so search by the first word of the address and keep exact
	// address matches.
	words := contactWords(email)
	if len(words) == 0 {
		return nil
	}
	hits, err := h.searchVisibleContacts(r, words[0], 50, true)
	if err != nil {
		return err
	}
	var chosen *visibleContactHit
	for index := range hits {
		hit := &hits[index]
		if strings.EqualFold(hit.ContactKind, "group") || !slices.ContainsFunc(hit.addresses(), func(address *mail.Address) bool { return strings.EqualFold(address.Address, email) }) {
			continue
		}
		if chosen == nil || chosen.recentRecipient() && !hit.recentRecipient() {
			chosen = hit
		}
	}
	if chosen == nil {
		return nil
	}
	item, err := h.workspace.GetItem(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), chosen.ItemID)
	if errors.Is(err, service.ErrForbidden) || errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	contact := model.ParseVCard(item.Data)
	card.Name, card.Title, card.Org = strings.TrimSpace(contact.FN), contact.Title, contact.Org
	card.Emails = []string{email}
	for _, value := range contact.Emails {
		if address, err := mail.ParseAddress(value); err == nil && !slices.Contains(card.Emails, strings.ToLower(address.Address)) {
			card.Emails = append(card.Emails, strings.ToLower(address.Address))
		}
	}
	card.Phones = append(card.Phones, contact.Phones...)
	if len(contact.PhotoData) > 0 {
		card.PhotoURL = contactSuggestionPhotoURL(service.SearchHit{ItemID: item.ID, ContactHasPhoto: true, Updated: item.UpdatedAt})
	}
	if !chosen.recentRecipient() {
		card.Contact = &personCardContact{ItemID: item.ID, FolderID: chosen.Folder.ID, Addressbook: chosen.Folder.Name}
		card.Favorite = h.favoriteContacts(r)[item.ID]
	}
	return nil
}

func (h *Handler) cardRecentMessages(r *http.Request, email string, card *personCard) error {
	if h.search == nil {
		return service.ErrSearchUnavailable
	}
	page, err := h.search.Search(r.Context(), webAccess(currentActor(r), currentSubject(r), currentActingMode(r)), service.SearchQuery{
		AccountID: currentSubject(r).ID, Types: []model.FolderType{model.FolderTypeMail},
		Filter: &service.SearchFilter{Operator: service.SearchContains, Field: "from", Value: email},
		Sort:   "date_desc", Limit: maxCardRecentMessages, OmitSnippets: true,
	})
	if err != nil {
		return err
	}
	for _, hit := range page.Hits {
		if len(card.Recent) >= maxCardRecentMessages {
			break
		}
		card.Recent = append(card.Recent, personCardMessage{ItemID: hit.ItemID, FolderID: hit.FolderID, FolderName: hit.FolderName, Subject: firstNonEmptyString(hit.Title, hit.Name), Date: hit.Date, Unread: !slices.Contains(hit.Flags, model.FlagSeen)})
	}
	return nil
}

// cardUpcomingMeetings reads the calendar range index of the subject's own
// calendars for the next cardUpcomingWindow and keeps occurrences that list
// email as organizer or attendee.
func (h *Handler) cardUpcomingMeetings(r *http.Request, email string, card *personCard) error {
	access := webAccess(currentActor(r), currentSubject(r), currentActingMode(r))
	folders, err := h.folderSpace.ListFolders(r.Context(), access, service.FolderQuery{Type: model.FolderTypeCalendar})
	if err != nil {
		return err
	}
	start := time.Now().UTC()
	end := start.Add(cardUpcomingWindow)
	type meeting struct {
		at   time.Time
		view personCardMeeting
	}
	var meetings []meeting
	calendars := 0
	for _, folder := range folders {
		if folder.Type != model.FolderTypeCalendar || !strings.EqualFold(folder.UserID, currentSubject(r).ID) || calendars >= maxCardCalendars {
			continue
		}
		calendars++
		// Keep the full-item listing authorization boundary the calendar
		// view uses, even when a ready projection could answer alone.
		if folder.ItemCount > 0 {
			if _, err := h.workspace.ListFullItemPage(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r), folder.ID, 0, 1); err != nil {
				continue
			}
		}
		results, err := h.calendarIndex.Query(r.Context(), h.folderSpace, access, folder, start, end)
		if err != nil {
			continue
		}
		for _, result := range results {
			event := result.Occurrence.Event
			if strings.EqualFold(event.Status, "CANCELLED") || !eventInvolves(event, email) {
				continue
			}
			from, _, ok := calendarindex.OccupiedBounds(event)
			if !ok {
				continue
			}
			meetings = append(meetings, meeting{at: from, view: personCardMeeting{ID: result.ItemID, FolderID: result.FolderID, Summary: event.Summary, Start: event.Start, End: event.End, AllDay: event.AllDay, Location: event.Location}})
		}
	}
	sort.SliceStable(meetings, func(i, j int) bool { return meetings[i].at.Before(meetings[j].at) })
	for _, entry := range meetings {
		if len(card.Upcoming) >= maxCardUpcoming {
			break
		}
		card.Upcoming = append(card.Upcoming, entry.view)
	}
	return nil
}

func eventInvolves(event calendarcore.Event, email string) bool {
	matches := func(value string) bool {
		value = strings.TrimSpace(value)
		if trimmed, found := strings.CutPrefix(strings.ToLower(value), "mailto:"); found {
			value = trimmed
		}
		if address, err := mail.ParseAddress(value); err == nil {
			value = address.Address
		}
		return strings.EqualFold(value, email)
	}
	if matches(event.OrganizerAddress) {
		return true
	}
	for _, participant := range event.Participants {
		if matches(participant.Address) {
			return true
		}
	}
	return slices.ContainsFunc(event.Attendees, matches)
}

type searchOperatorSuggestion struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

var searchOperatorSuggestions = []searchOperatorSuggestion{
	{"from:", "Sent by a person"}, {"to:", "Sent to a person"}, {"subject:", "Words in the subject"},
	{"has:attachment", "Has an attachment"}, {"is:unread", "Unread messages"}, {"is:flagged", "Flagged messages"},
	{"filename:", "Attachment or file name"}, {"after:", "On or after a date (YYYY-MM-DD)"}, {"before:", "Before a date (YYYY-MM-DD)"},
	{"type:mail", "Only mail"}, {"type:calendar", "Only calendar events"}, {"type:contacts", "Only contacts"}, {"type:files", "Only files"},
}

type searchPersonSuggestion struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Source   string `json:"source"`
	PhotoURL string `json:"photo_url,omitempty"`
	// Value is the complete query to run for this suggestion.
	Value string `json:"value"`
}

type searchSavedSuggestion struct {
	ID    string              `json:"id"`
	Name  string              `json:"name"`
	Query service.SearchQuery `json:"query"`
}

type searchFolderSuggestion struct {
	ID   string           `json:"id"`
	Name string           `json:"name"`
	Path string           `json:"path"`
	Type model.FolderType `json:"type"`
}

type searchSuggestions struct {
	People        []searchPersonSuggestion   `json:"people"`
	SavedSearches []searchSavedSuggestion    `json:"saved_searches"`
	Folders       []searchFolderSuggestion   `json:"folders"`
	Operators     []searchOperatorSuggestion `json:"operators"`
}

// apiSearchSuggestions offers bounded typed suggestions for a search box:
// people (visible contacts, recent recipients, same-domain directory), the
// actor's saved searches, readable folder names, and query operators. The
// last word of q is what people, folders, and operators complete.
func (h *Handler) apiSearchSuggestions(w http.ResponseWriter, r *http.Request) {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	if utf8.RuneCountInString(query) > maxSearchSuggestionQuery {
		jsonError(w, http.StatusBadRequest, "query is too long")
		return
	}
	scope := model.FolderType(strings.ToLower(strings.TrimSpace(r.URL.Query().Get("scope"))))
	switch scope {
	case "", "all":
		scope = ""
	case model.FolderTypeMail, model.FolderTypeCalendar, model.FolderTypeContacts, model.FolderTypeFiles:
	default:
		jsonError(w, http.StatusBadRequest, "scope must be all, mail, calendar, contacts, or files")
		return
	}
	limit := boundedLimit(r, 5, maxSearchSuggestions)
	prefix, last := "", query
	if index := strings.LastIndexAny(query, " \t"); index >= 0 {
		prefix, last = query[:index+1], query[index+1:]
	}
	lowerLast := strings.ToLower(last)
	result := searchSuggestions{People: []searchPersonSuggestion{}, SavedSearches: []searchSavedSuggestion{}, Folders: []searchFolderSuggestion{}, Operators: []searchOperatorSuggestion{}}

	for _, operator := range searchOperatorSuggestions {
		if len(result.Operators) >= limit {
			break
		}
		// A scope already fixes the type; mail-only operators need mail.
		general := operator.Value == "filename:" || operator.Value == "after:" || operator.Value == "before:"
		if scope != "" && strings.HasPrefix(operator.Value, "type:") || scope != "" && scope != model.FolderTypeMail && !general {
			continue
		}
		if lowerLast == "" || !strings.Contains(lowerLast, ":") && strings.HasPrefix(operator.Value, lowerLast) && operator.Value != lowerLast {
			result.Operators = append(result.Operators, searchOperatorSuggestion{Value: prefix + operator.Value, Label: operator.Label})
		}
	}

	personOperator, personQuery := "from:", last
	if name, value, found := strings.Cut(last, ":"); found {
		personOperator, personQuery = strings.ToLower(name)+":", value
		if personOperator != "from:" && personOperator != "to:" && personOperator != "cc:" {
			personQuery = ""
		}
	}
	if (scope == "" || scope == model.FolderTypeMail) && utf8.RuneCountInString(personQuery) >= 2 {
		people, err := h.rankedPeople(r, personQuery, limit)
		if err != nil && !errors.Is(err, service.ErrSearchUnavailable) {
			apiError(w, err)
			return
		}
		for _, person := range people {
			if person.Kind != "person" || person.Email == "" {
				continue
			}
			result.People = append(result.People, searchPersonSuggestion{Name: person.Name, Email: person.Email, Source: person.Source, PhotoURL: person.PhotoURL, Value: prefix + personOperator + person.Email})
		}
	}

	if h.savedSearches != nil {
		definitions, err := h.savedSearches.List(r.Context(), currentActor(r).ID)
		if err != nil {
			apiError(w, err)
			return
		}
		lowerQuery := strings.ToLower(query)
		for _, definition := range definitions {
			if len(result.SavedSearches) >= limit {
				break
			}
			if lowerQuery == "" || strings.Contains(strings.ToLower(definition.Name), lowerQuery) {
				result.SavedSearches = append(result.SavedSearches, searchSavedSuggestion{ID: definition.ID, Name: definition.Name, Query: definition.Query})
			}
		}
	}

	if lowerLast != "" && !strings.Contains(lowerLast, ":") {
		folders, err := h.workspace.ListFolders(r.Context(), currentActor(r), currentSubject(r), currentActingMode(r))
		if err != nil {
			apiError(w, err)
			return
		}
		for _, folder := range folders {
			if len(result.Folders) >= limit {
				break
			}
			searchable := folder.Type == model.FolderTypeMail || folder.Type == model.FolderTypeCalendar || folder.Type == model.FolderTypeContacts || folder.Type == model.FolderTypeFiles
			if !searchable || scope != "" && folder.Type != scope || !folder.TrashedAt.IsZero() {
				continue
			}
			if strings.Contains(strings.ToLower(folder.Name), lowerLast) {
				result.Folders = append(result.Folders, searchFolderSuggestion{ID: folder.ID, Name: folder.Name, Path: folder.Path, Type: folder.Type})
			}
		}
	}
	jsonResponse(w, http.StatusOK, result)
}
