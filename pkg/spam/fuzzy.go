package spam

import (
	"container/list"
	"encoding/json"
	"hash/fnv"
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
)

// Fuzzy and bulk detection defaults. A signature is the MinHash of a
// message's four-word shingles; two messages are similar to the degree
// their signatures agree.
const (
	DefaultFuzzyThreshold  = 80 // percent similarity
	DefaultBulkThreshold   = 5  // distinct senders
	DefaultFuzzyMaxEntries = 5_000
	DefaultFuzzyHalfLife   = 14 * 24 * time.Hour
	DefaultBulkWindow      = time.Hour
	DefaultBulkMaxEntries  = 2_000

	SymbolFuzzySpam      = "FUZZY_SPAM"
	SymbolBulkSameBody   = "BULK_SAME_BODY"
	SymbolBulkNewsletter = "BULK_NEWSLETTER"

	fuzzySignatureSize = 64
	fuzzyShingleWords  = 4
	fuzzyMinWords      = 20
	fuzzyMaxWords      = 4_000
	// fuzzyBulkSimilarity is how alike two bodies must be to count as the
	// same bulk mailing.
	fuzzyBulkSimilarity = 0.9
	// Weights: a user's Junk move against one automatic judgement, and the
	// weight at which a match scores at full strength.
	fuzzyUserWeight = 3.0
	fuzzyAutoWeight = 1.0
	fuzzyFullWeight = 2.0
	fuzzyMinWeight  = 0.1
	bulkMaxSenders  = 64

	fuzzySymbolPrefix = "FUZZY_"
	bulkSymbolPrefix  = "BULK_"
)

func init() {
	builtinSymbols[SymbolFuzzySpam] = symbolInfo{4.0, "Body closely matches mail users or the filter learned to be spam"}
	builtinSymbols[SymbolBulkSameBody] = symbolInfo{2.5, "Near-identical body arriving from many unrelated senders"}
	builtinSymbols[SymbolBulkNewsletter] = symbolInfo{0, "Bulk body from a DKIM-signed sender offering List-Unsubscribe"}
}

// signature is a MinHash sketch of a message body.
type signature [fuzzySignatureSize]uint32

var (
	fuzzyURL   = regexp.MustCompile(`(?i)\b(?:https?://|www\.)\S+`)
	fuzzyEmail = regexp.MustCompile(`\S+@\S+`)
)

// fuzzyWords normalizes decoded body text for shingling: lower-cased
// letter-only words, without URLs, addresses, numbers, and quoted replies,
// so numbers, links, and spacing may vary freely.
func fuzzyWords(texts []string) []string {
	var words []string
	for _, text := range texts {
		for line := range strings.Lines(text) {
			if strings.HasPrefix(strings.TrimSpace(line), ">") {
				continue
			}
			line = fuzzyEmail.ReplaceAllString(fuzzyURL.ReplaceAllString(line, " "), " ")
			for _, word := range strings.FieldsFunc(strings.ToLower(line), func(r rune) bool { return !unicode.IsLetter(r) }) {
				if len(words) >= fuzzyMaxWords {
					return words
				}
				if len([]rune(word)) > 1 {
					words = append(words, word)
				}
			}
		}
	}
	return words
}

// newSignature sketches words; false when the text is too short to compare.
func newSignature(words []string) (signature, bool) {
	var sig signature
	if len(words) < fuzzyMinWords {
		return sig, false
	}
	for i := range sig {
		sig[i] = math.MaxUint32
	}
	for i := 0; i+fuzzyShingleWords <= len(words); i++ {
		hash := fnv.New64a()
		for _, word := range words[i : i+fuzzyShingleWords] {
			hash.Write([]byte(word))
			hash.Write([]byte{0})
		}
		base := hash.Sum64()
		for slot := range sig {
			if value := uint32(mix64(base + uint64(slot)*0x9e3779b97f4a7c15)); value < sig[slot] {
				sig[slot] = value
			}
		}
	}
	return sig, true
}

// mix64 is the splitmix64 finalizer.
func mix64(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	return x ^ x>>31
}

// similarity is the share of slots on which a and b agree.
func (a signature) similarity(b signature) float64 {
	same := 0
	for i := range a {
		if a[i] == b[i] {
			same++
		}
	}
	return float64(same) / fuzzySignatureSize
}

// messageSignature sketches a message's visible text.
func messageSignature(body content) (signature, bool) {
	return newSignature(fuzzyWords(append(append([]string(nil), body.text...), body.htmlText...)))
}

// Fuzzy is the server-wide local fuzzy and bulk detector: a bounded,
// decayed store of spam body signatures fed by users' Junk moves and by
// high-scoring deliveries, and a short window of recent bodies with the
// distinct senders that sent them. Its zero value is enabled with the
// default bounds and clock; it is safe for concurrent use.
type Fuzzy struct {
	mu      sync.Mutex
	spam    list.List // *fuzzyEntry, front is most recently updated
	recent  list.List // *bulkEntry, front is most recently seen
	disable atomic.Bool

	threshold     atomic.Int64
	bulkThreshold atomic.Int64

	// MaxEntries, BulkMaxEntries, HalfLife, BulkWindow, and Now are fixed
	// before first use; zero values use the defaults.
	MaxEntries     int
	BulkMaxEntries int
	HalfLife       time.Duration
	BulkWindow     time.Duration
	Now            func() time.Time
}

type fuzzyEntry struct {
	sig     signature
	weight  float64
	updated time.Time
}

type bulkEntry struct {
	sig     signature
	senders map[uint64]struct{}
	seen    time.Time
}

// SetSettings applies the live switches: whether detection runs, the
// similarity percent two bodies need to match, and the distinct senders of
// one body that make it bulk.
func (f *Fuzzy) SetSettings(enabled bool, thresholdPercent, bulkThreshold int) {
	f.disable.Store(!enabled)
	f.threshold.Store(int64(thresholdPercent))
	f.bulkThreshold.Store(int64(bulkThreshold))
}

// Enabled reports whether detection runs.
func (f *Fuzzy) Enabled() bool { return f != nil && !f.disable.Load() }

func (f *Fuzzy) similarityThreshold() float64 {
	if percent := f.threshold.Load(); percent > 0 {
		return float64(percent) / 100
	}
	return DefaultFuzzyThreshold / 100.0
}

// BulkThreshold is the distinct senders of one body that make it bulk.
func (f *Fuzzy) BulkThreshold() int {
	if threshold := int(f.bulkThreshold.Load()); threshold > 0 {
		return threshold
	}
	return DefaultBulkThreshold
}

func (f *Fuzzy) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

func orDefault[T int | time.Duration](value, fallback T) T {
	if value > 0 {
		return value
	}
	return fallback
}

func (f *Fuzzy) decayed(entry *fuzzyEntry, now time.Time) float64 {
	weight := entry.weight
	if elapsed := now.Sub(entry.updated); elapsed > 0 {
		weight *= math.Exp2(-float64(elapsed) / float64(orDefault(f.HalfLife, DefaultFuzzyHalfLife)))
	}
	return weight
}

// learnLocked adds weight to the spam signature matching sig, or stores a
// new one, evicting the least recently updated beyond the cap.
func (f *Fuzzy) learnLocked(sig signature, weight float64) {
	now := f.now()
	if element, entry := f.matchSpamLocked(sig, now); element != nil {
		entry.weight = f.decayed(entry, now) + weight
		entry.updated = now
		f.spam.MoveToFront(element)
		return
	}
	f.spam.PushFront(&fuzzyEntry{sig: sig, weight: weight, updated: now})
	for f.spam.Len() > orDefault(f.MaxEntries, DefaultFuzzyMaxEntries) {
		f.spam.Remove(f.spam.Back())
	}
}

// matchSpamLocked returns the most similar stored spam signature at or above
// the threshold that still carries weight.
func (f *Fuzzy) matchSpamLocked(sig signature, now time.Time) (*list.Element, *fuzzyEntry) {
	var best *list.Element
	var bestEntry *fuzzyEntry
	bestSimilarity := f.similarityThreshold() - 1e-9
	for element := f.spam.Front(); element != nil; element = element.Next() {
		entry := element.Value.(*fuzzyEntry)
		if similarity := sig.similarity(entry.sig); similarity > bestSimilarity && f.decayed(entry, now) >= fuzzyMinWeight {
			best, bestEntry, bestSimilarity = element, entry, similarity
		}
	}
	return best, bestEntry
}

// Moved learns a user's Junk move of the message raw: its body becomes (or
// strengthens) a spam signature. A Not-junk move forgets every signature the
// message matches, so a false positive stops matching at once.
func (f *Fuzzy) Moved(raw []byte, junk bool) {
	if !f.Enabled() {
		return
	}
	sig, ok := messageSignature(parseContent(raw))
	if !ok {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if junk {
		f.learnLocked(sig, fuzzyUserWeight)
		return
	}
	threshold := f.similarityThreshold()
	for element := f.spam.Front(); element != nil; {
		next := element.Next()
		if sig.similarity(element.Value.(*fuzzyEntry).sig) >= threshold {
			f.spam.Remove(element)
		}
		element = next
	}
}

// scoreFuzzy adds FUZZY_SPAM, BULK_SAME_BODY, or BULK_NEWSLETTER for m's
// body, then learns the body when the message is otherwise judged spam.
// Learning ignores fuzzy and bulk symbols so detection never feeds on
// itself; mail from private and trusted networks is neither counted nor
// learned.
func (e *Engine) scoreFuzzy(symbols *symbolSet, headers map[string]string, body content, m Message) {
	fuzzy := e.config.Fuzzy
	if !fuzzy.Enabled() || e.addressSkip(m.RemoteIP) != "" {
		return
	}
	sig, ok := messageSignature(body)
	if !ok {
		return
	}
	fuzzy.mu.Lock()
	defer fuzzy.mu.Unlock()
	now := fuzzy.now()
	if element, entry := fuzzy.matchSpamLocked(sig, now); element != nil {
		similarity := sig.similarity(entry.sig)
		weight := fuzzy.decayed(entry, now)
		base := builtinSymbols[SymbolFuzzySpam]
		symbols.add(SymbolFuzzySpam, math.Round(base.score*similarity*min(1, weight/fuzzyFullWeight)*100)/100, base.description,
			"similarity="+strconv.Itoa(int(math.Round(similarity*100)))+"%", "weight="+formatScore(weight))
	}
	if count := fuzzy.observeBulkLocked(sig, bulkSender(m), now); count > fuzzy.BulkThreshold() {
		options := []string{"senders=" + strconv.Itoa(count)}
		if _, listed := headers["list-unsubscribe"]; listed && strings.EqualFold(m.DKIM, "pass") {
			symbols.builtin(SymbolBulkNewsletter, options...)
		} else {
			base := builtinSymbols[SymbolBulkSameBody]
			scale := min(1, float64(count)/float64(2*fuzzy.BulkThreshold()))
			symbols.add(SymbolBulkSameBody, math.Round(base.score*scale*100)/100, base.description, options...)
		}
	}
	var score float64
	for _, symbol := range symbols.symbols {
		if !strings.HasPrefix(symbol.Name, fuzzySymbolPrefix) && !strings.HasPrefix(symbol.Name, bulkSymbolPrefix) {
			score += symbol.Score
		}
	}
	if action := e.config.Thresholds.Action(score); action == ActionJunk || action == ActionReject {
		fuzzy.learnLocked(sig, fuzzyAutoWeight)
	}
}

// bulkSender identifies a sender for distinct counting: the authenticated or
// envelope domain together with the sending network.
func bulkSender(m Message) uint64 {
	domain := m.AuthDomain
	if domain == "" {
		domain = extractDomain(m.EnvelopeFrom)
	}
	hash := fnv.New64a()
	hash.Write([]byte(strings.ToLower(domain) + "|" + ReputationNetwork(m.RemoteIP)))
	return hash.Sum64()
}

// observeBulkLocked records sender for the body sig, returning the distinct
// senders of that body within the window.
func (f *Fuzzy) observeBulkLocked(sig signature, sender uint64, now time.Time) int {
	window := orDefault(f.BulkWindow, DefaultBulkWindow)
	for element := f.recent.Back(); element != nil && now.Sub(element.Value.(*bulkEntry).seen) > window; element = f.recent.Back() {
		f.recent.Remove(element)
	}
	var found *bulkEntry
	for element := f.recent.Front(); element != nil; element = element.Next() {
		if entry := element.Value.(*bulkEntry); sig.similarity(entry.sig) >= fuzzyBulkSimilarity {
			found = entry
			f.recent.MoveToFront(element)
			break
		}
	}
	if found == nil {
		found = &bulkEntry{sig: sig, senders: make(map[uint64]struct{})}
		f.recent.PushFront(found)
		for f.recent.Len() > orDefault(f.BulkMaxEntries, DefaultBulkMaxEntries) {
			f.recent.Remove(f.recent.Back())
		}
	}
	found.seen = now
	if len(found.senders) < bulkMaxSenders {
		found.senders[sender] = struct{}{}
	}
	return len(found.senders)
}

// FuzzyReport describes the detector's settings and occupancy.
type FuzzyReport struct {
	Enabled       bool `json:"enabled"`
	Threshold     int  `json:"threshold"`
	BulkThreshold int  `json:"bulk_threshold"`
	Signatures    int  `json:"signatures"`
	RecentBodies  int  `json:"recent_bodies"`
}

// Report returns the detector's settings and occupancy.
func (f *Fuzzy) Report() FuzzyReport {
	f.mu.Lock()
	defer f.mu.Unlock()
	return FuzzyReport{
		Enabled: f.Enabled(), Threshold: int(math.Round(f.similarityThreshold() * 100)), BulkThreshold: f.BulkThreshold(),
		Signatures: f.spam.Len(), RecentBodies: f.recent.Len(),
	}
}

// Reset forgets every signature and recent body.
func (f *Fuzzy) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.spam.Init()
	f.recent.Init()
}

type fuzzySnapshot struct {
	Sig     signature `json:"s"`
	Weight  float64   `json:"w"`
	Updated time.Time `json:"u"`
}

// Snapshot serializes the spam signatures, least recently updated first so
// Restore rebuilds the same order. The short bulk window is not persisted.
func (f *Fuzzy) Snapshot() ([]byte, error) {
	f.mu.Lock()
	snapshot := make([]fuzzySnapshot, 0, f.spam.Len())
	for element := f.spam.Back(); element != nil; element = element.Prev() {
		entry := element.Value.(*fuzzyEntry)
		snapshot = append(snapshot, fuzzySnapshot{Sig: entry.sig, Weight: entry.weight, Updated: entry.updated})
	}
	f.mu.Unlock()
	return json.Marshal(snapshot)
}

// Restore replaces the signatures with a Snapshot, keeping at most
// MaxEntries of the most recently updated.
func (f *Fuzzy) Restore(data []byte) error {
	var snapshot []fuzzySnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.spam.Init()
	for _, item := range snapshot {
		if item.Weight > 0 {
			f.spam.PushFront(&fuzzyEntry{sig: item.Sig, weight: item.Weight, updated: item.Updated})
		}
	}
	for f.spam.Len() > orDefault(f.MaxEntries, DefaultFuzzyMaxEntries) {
		f.spam.Remove(f.spam.Back())
	}
	return nil
}

// MoveFeedback fans users' explicit Junk and Not-junk moves out to sender
// reputation and the fuzzy detector; either may be nil. It implements
// bayes.Feedback.
type MoveFeedback struct {
	Reputation *Reputation
	Fuzzy      *Fuzzy
}

// Moved credits the moved message's sender and learns or forgets its body.
func (m MoveFeedback) Moved(raw []byte, headers map[string]string, junk bool) {
	if m.Reputation != nil {
		m.Reputation.Moved(headers, junk)
	}
	if m.Fuzzy != nil {
		m.Fuzzy.Moved(raw, junk)
	}
}
