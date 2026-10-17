package main

import (
	"strings"
	"testing"
	"time"
)

func newTestStore(max int) *Store {
	return NewStore(StoreConfig{MaxEntries: max, MaxBytes: 1 << 20, MaxTTL: 5 * time.Minute})
}

func ttl(d time.Duration) PutOpts { return PutOpts{TTL: d} }

func TestPutGetRoundTrip(t *testing.T) {
	s := newTestStore(8)
	if err := s.Put("a", []byte("hi"), ttl(time.Minute)); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, ok := s.Get("a")
	if !ok || string(got) != "hi" {
		t.Fatalf("get = %q,%v want hi,true", got, ok)
	}
	// multi-read: still there.
	if _, ok := s.Get("a"); !ok {
		t.Fatal("entry should survive a non-burn read")
	}
}

func TestBurnDeletesOnRead(t *testing.T) {
	s := newTestStore(8)
	_ = s.Put("a", []byte("secret"), PutOpts{TTL: time.Minute, Burn: true})
	if got, ok := s.Get("a"); !ok || string(got) != "secret" {
		t.Fatalf("first read = %q,%v", got, ok)
	}
	if _, ok := s.Get("a"); ok {
		t.Fatal("burn entry should be gone after first read")
	}
}

func TestTTLExpiry(t *testing.T) {
	s := newTestStore(8)
	base := time.Now()
	s.now = func() time.Time { return base }
	_ = s.Put("a", []byte("v"), ttl(30*time.Second))
	s.now = func() time.Time { return base.Add(31 * time.Second) }
	if _, ok := s.Get("a"); ok {
		t.Fatal("entry should expire after its TTL")
	}
}

func TestWriteOnceWhileLive(t *testing.T) {
	s := newTestStore(8)
	if err := s.Put("a", []byte("v1"), ttl(time.Minute)); err != nil {
		t.Fatalf("first put: %v", err)
	}
	if err := s.Put("a", []byte("v2"), ttl(time.Minute)); err != ErrExists {
		t.Fatalf("second put err = %v, want ErrExists", err)
	}
}

func TestReplaceSlotLastWriteWins(t *testing.T) {
	s := newTestStore(8)
	if err := s.Put("clip", []byte("v1"), PutOpts{TTL: time.Minute, Replace: true}); err != nil {
		t.Fatalf("first replace put: %v", err)
	}
	if err := s.Put("clip", []byte("v2"), PutOpts{TTL: time.Minute, Replace: true}); err != nil {
		t.Fatalf("second replace put err = %v, want nil", err)
	}
	if got, ok := s.Get("clip"); !ok || string(got) != "v2" {
		t.Fatalf("replace get = %q,%v want v2,true", got, ok)
	}
}

func TestExpiredNameReclaimable(t *testing.T) {
	s := newTestStore(8)
	base := time.Now()
	s.now = func() time.Time { return base }
	_ = s.Put("a", []byte("v1"), ttl(10*time.Second))
	s.now = func() time.Time { return base.Add(11 * time.Second) }
	if err := s.Put("a", []byte("v2"), ttl(time.Minute)); err != nil {
		t.Fatalf("reclaim expired name: %v", err)
	}
}

func TestMaxEntriesFull(t *testing.T) {
	s := newTestStore(2)
	_ = s.Put("a", []byte("1"), ttl(time.Minute))
	_ = s.Put("b", []byte("2"), ttl(time.Minute))
	if err := s.Put("c", []byte("3"), ttl(time.Minute)); err != ErrFull {
		t.Fatalf("put past cap err = %v, want ErrFull", err)
	}
}

func TestMaxTotalBytesBudget(t *testing.T) {
	s := NewStore(StoreConfig{MaxEntries: 100, MaxBytes: 1 << 20, MaxTotalBytes: 10, MaxTTL: time.Minute})
	if err := s.Put("a", []byte("12345"), ttl(time.Minute)); err != nil {
		t.Fatalf("5-byte put under 10-byte budget: %v", err)
	}
	if err := s.Put("b", []byte("123456"), ttl(time.Minute)); err != ErrFull {
		t.Fatalf("over-budget put err = %v, want ErrFull", err)
	}
	// Replacing 'a' with a smaller value frees budget for 'b'.
	if err := s.Put("a", []byte("1"), PutOpts{TTL: time.Minute, Replace: true}); err != nil {
		t.Fatalf("shrink replace: %v", err)
	}
	if err := s.Put("b", []byte("123456"), ttl(time.Minute)); err != nil {
		t.Fatalf("put after freeing budget: %v", err)
	}
	if got := s.Bytes(); got != 7 {
		t.Fatalf("curBytes = %d, want 7", got)
	}
}

func TestBytesAccountingAfterBurnAndExpire(t *testing.T) {
	s := newTestStore(8)
	base := time.Now()
	s.now = func() time.Time { return base }
	_ = s.Put("burn", []byte("xxxx"), PutOpts{TTL: time.Minute, Burn: true})
	_ = s.Put("exp", []byte("yy"), ttl(10*time.Second))
	if s.Bytes() != 6 {
		t.Fatalf("curBytes = %d, want 6", s.Bytes())
	}
	_, _ = s.Get("burn") // burns → frees 4
	if s.Bytes() != 2 {
		t.Fatalf("curBytes after burn = %d, want 2", s.Bytes())
	}
	s.now = func() time.Time { return base.Add(time.Minute) }
	_ = s.Len() // prunes the expired 'exp' → frees 2
	if s.Bytes() != 0 {
		t.Fatalf("curBytes after expire = %d, want 0", s.Bytes())
	}
}

func TestClampTTL(t *testing.T) {
	s := NewStore(StoreConfig{MaxEntries: 4, MaxBytes: 1 << 20, MaxTTL: time.Minute})
	base := time.Now()
	s.now = func() time.Time { return base }
	_ = s.Put("a", []byte("v"), ttl(time.Hour)) // request exceeds MaxTTL
	s.now = func() time.Time { return base.Add(61 * time.Second) }
	if _, ok := s.Get("a"); ok {
		t.Fatal("TTL should be clamped to MaxTTL")
	}
}

func TestRandIDShapeAndUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id := randID(idLen)
		if len(id) != idLen {
			t.Fatalf("id %q len = %d, want %d", id, len(id), idLen)
		}
		for _, c := range id {
			if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
				t.Fatalf("id %q has non-base62 char %q", id, c)
			}
		}
		if seen[id] {
			t.Fatalf("duplicate id %q within 1000 draws", id)
		}
		seen[id] = true
	}
}

func TestPutRandomUnique(t *testing.T) {
	s := newTestStore(0) // 0 = no cap
	ids := make(map[string]bool)
	for i := 0; i < 500; i++ {
		id, err := s.PutRandom([]byte("x"), ttl(time.Minute), idLen)
		if err != nil {
			t.Fatalf("PutRandom: %v", err)
		}
		if ids[id] {
			t.Fatalf("PutRandom returned duplicate id %q", id)
		}
		ids[id] = true
	}
}

func TestWordsListIs256Unique(t *testing.T) {
	if len(words) != 256 {
		t.Fatalf("words list has %d entries, want exactly 256", len(words))
	}
	seen := make(map[string]bool, len(words))
	for _, w := range words {
		if seen[w] {
			t.Fatalf("duplicate word %q in list", w)
		}
		seen[w] = true
	}
}

func TestWordCodeShape(t *testing.T) {
	for i := 0; i < 200; i++ {
		code := randWordCode()
		if n := strings.Count(code, "-"); n != 3 {
			t.Fatalf("word code %q has %d separators, want 3", code, n)
		}
		for _, part := range strings.Split(code, "-") {
			if part == "" {
				t.Fatalf("word code %q has an empty part", code)
			}
		}
	}
}
