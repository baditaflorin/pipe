package main

import (
	"crypto/rand"
	"errors"
	"sync"
	"time"
)

// idAlphabet is base62 — alnum only, so ids are double-click selectable and
// safe in a URL path with no escaping.
const idAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

var (
	// ErrExists — a named slot is already live (write-once within the TTL,
	// unless PutOpts.Replace is set).
	ErrExists = errors.New("name already taken")
	// ErrFull — the store is at MaxEntries or MaxTotalBytes; retry once
	// something expires.
	ErrFull = errors.New("store full")
)

// PutOpts carries the per-write knobs. Grouping them keeps the call sites
// readable as features (burn, replace, notify, …) accumulate.
type PutOpts struct {
	TTL        time.Duration
	Burn       bool   // delete on first read
	Replace    bool   // overwrite a live name instead of 409 (last-write-wins slots)
	Notify     bool   // arm a read-receipt: record ReadAt + signal watchers on first read
	WatchToken string // secret the creator presents to watch read-status (Notify only)
}

type item struct {
	data    []byte
	expires time.Time
	burn    bool

	// read-receipt (Notify) support — zero-valued and unused unless armed.
	notify     bool
	readAt     time.Time
	readCh     chan struct{} // closed exactly once on the first read; nil if not armed
	watchToken string        // creator's secret for the watch endpoint
}

func (it *item) size() int64 { return int64(len(it.data)) }

// StoreConfig holds the immutable knobs for a Store.
type StoreConfig struct {
	MaxEntries    int
	MaxBytes      int64 // per-blob cap (enforced in the handler, mirrored here for docs)
	MaxTotalBytes int64 // total in-RAM budget across all live entries; <=0 disables
	MaxTTL        time.Duration
}

// Store is an in-memory, TTL-bounded blob store. Nothing touches disk — a
// process restart wipes it, which is a feature for an ephemeral relay.
type Store struct {
	mu       sync.Mutex
	items    map[string]*item
	curBytes int64 // running sum of len(item.data) over live entries
	cfg      StoreConfig

	// now is injectable so tests can advance the clock without sleeping.
	now func() time.Time

	stop chan struct{}
}

// NewStore builds an empty store. MaxEntries < 1 disables the count cap;
// MaxTotalBytes < 1 disables the byte budget.
func NewStore(cfg StoreConfig) *Store {
	return &Store{
		items: make(map[string]*item),
		cfg:   cfg,
		now:   time.Now,
		stop:  make(chan struct{}),
	}
}

// removeLocked deletes k (if present) and keeps curBytes in sync. Returns the
// removed item so callers can signal watchers, etc.
func (s *Store) removeLocked(k string) *item {
	it, ok := s.items[k]
	if !ok {
		return nil
	}
	s.curBytes -= it.size()
	delete(s.items, k)
	return it
}

// admitLocked checks the count + byte budgets for storing newSize bytes, given
// that oldSize bytes for the same key are being displaced (0 for a fresh key).
func (s *Store) admitLocked(newKey bool, newSize, oldSize int64) error {
	if newKey && s.cfg.MaxEntries > 0 && len(s.items) >= s.cfg.MaxEntries {
		return ErrFull
	}
	if s.cfg.MaxTotalBytes > 0 && s.curBytes-oldSize+newSize > s.cfg.MaxTotalBytes {
		return ErrFull
	}
	return nil
}

// Put stores data under an explicit name. Write-once by default: if the name is
// still live it returns ErrExists (the caller maps that to 409). With
// o.Replace it overwrites the live entry instead (last-write-wins). An expired
// name is always reclaimable.
func (s *Store) Put(name string, data []byte, o PutOpts) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()

	var oldSize int64
	newKey := true
	if it, ok := s.items[name]; ok && s.now().Before(it.expires) {
		if !o.Replace {
			return ErrExists
		}
		oldSize = it.size()
		newKey = false
	}
	if err := s.admitLocked(newKey, int64(len(data)), oldSize); err != nil {
		return err
	}
	s.curBytes += int64(len(data)) - oldSize
	s.items[name] = s.newItem(data, o)
	return nil
}

// PutRandom stores data under a freshly generated unguessable base62 id.
func (s *Store) PutRandom(data []byte, o PutOpts, n int) (string, error) {
	return s.putGenerated(data, o, func() string { return randID(n) })
}

// PutWords stores data under a freshly generated human word-code id (see
// words.go). Same collision-retry contract as PutRandom.
func (s *Store) PutWords(data []byte, o PutOpts) (string, error) {
	return s.putGenerated(data, o, randWordCode)
}

// putGenerated is the shared body for PutRandom/PutWords: try the generator a
// few times to dodge collisions, then store.
func (s *Store) putGenerated(data []byte, o PutOpts, gen func() string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	if err := s.admitLocked(true, int64(len(data)), 0); err != nil {
		return "", err
	}
	var id string
	for tries := 0; tries < 8; tries++ {
		candidate := gen()
		if _, clash := s.items[candidate]; !clash {
			id = candidate
			break
		}
	}
	if id == "" {
		return "", ErrFull
	}
	s.curBytes += int64(len(data))
	s.items[id] = s.newItem(data, o)
	return id, nil
}

func (s *Store) newItem(data []byte, o PutOpts) *item {
	it := &item{data: data, expires: s.now().Add(s.clampTTL(o.TTL)), burn: o.Burn}
	if o.Notify {
		it.notify = true
		it.readCh = make(chan struct{})
		it.watchToken = o.WatchToken
	}
	return it
}

// Get returns the stored bytes if present and unexpired. A burn entry is
// deleted as part of the read. The first read of a Notify entry stamps ReadAt
// and closes its watch channel.
func (s *Store) Get(id string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	it, ok := s.items[id]
	if !ok || !s.now().Before(it.expires) {
		if ok {
			s.removeLocked(id) // opportunistically reap the expired entry
		}
		return nil, false
	}
	if it.notify && it.readAt.IsZero() {
		it.readAt = s.now()
		if it.readCh != nil {
			close(it.readCh)
		}
	}
	if it.burn {
		s.removeLocked(id)
	}
	return it.data, true
}

// ReadStatus reports a Notify entry's watch token, whether it's been read yet,
// and a channel that closes on the first read. ok=false means no such (armed,
// live) entry.
func (s *Store) ReadStatus(id string) (token string, readAt time.Time, ch <-chan struct{}, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	it, live := s.items[id]
	if !live || !it.notify || !s.now().Before(it.expires) {
		return "", time.Time{}, nil, false
	}
	return it.watchToken, it.readAt, it.readCh, true
}

// Delete removes an entry if present (best-effort early delete).
func (s *Store) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeLocked(id)
}

// Len reports the number of live (post-prune) entries.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	return len(s.items)
}

// Bytes reports the current in-RAM total across live entries.
func (s *Store) Bytes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.curBytes
}

// StartJanitor periodically reaps expired entries so memory is reclaimed even
// for blobs nobody reads. Safe to call once.
func (s *Store) StartJanitor(every time.Duration) {
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				s.mu.Lock()
				s.pruneLocked()
				s.mu.Unlock()
			case <-s.stop:
				return
			}
		}
	}()
}

// StopJanitor halts the background reaper (used by tests).
func (s *Store) StopJanitor() { close(s.stop) }

func (s *Store) pruneLocked() {
	now := s.now()
	for k, it := range s.items {
		if !now.Before(it.expires) {
			s.curBytes -= it.size()
			delete(s.items, k)
		}
	}
}

func (s *Store) clampTTL(ttl time.Duration) time.Duration {
	if ttl <= 0 || ttl > s.cfg.MaxTTL {
		return s.cfg.MaxTTL
	}
	return ttl
}

// randID returns an n-char base62 id from crypto/rand using rejection
// sampling to avoid modulo bias.
func randID(n int) string {
	out := make([]byte, n)
	buf := make([]byte, n)
	const max = 256 - (256 % len(idAlphabet)) // largest unbiased byte value
	got := 0
	for got < n {
		if _, err := rand.Read(buf); err != nil {
			// crypto/rand failing is catastrophic; fall back to a fixed
			// char so we never emit an empty/predictable id silently.
			panic("pipe: crypto/rand unavailable: " + err.Error())
		}
		for _, b := range buf {
			if int(b) >= max {
				continue // reject biased tail
			}
			out[got] = idAlphabet[int(b)%len(idAlphabet)]
			got++
			if got == n {
				break
			}
		}
	}
	return string(out)
}
