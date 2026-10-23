package domain_test

import (
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/laenenai/audit/internal/domain"
)

func TestNewEventIDIsHexAndSortsByTime(t *testing.T) {
	t.Parallel()

	clock := domain.NewFixedClock(time.Date(2026, time.October, 23, 9, 0, 0, 0, time.UTC))

	var ids []string
	for i := 0; i < 8; i++ {
		id, err := domain.NewEventID(clock)
		if err != nil {
			t.Fatalf("NewEventID: %v", err)
		}
		if _, err := domain.ParseEventID(string(id)); err != nil {
			t.Fatalf("ParseEventID(%q): %v", id, err)
		}
		ids = append(ids, string(id))
		clock.Advance(time.Millisecond)
	}

	sorted := make([]string, len(ids))
	copy(sorted, ids)
	sort.Strings(sorted)
	for i := range ids {
		if ids[i] != sorted[i] {
			t.Fatalf("ids do not sort lexicographically by mint time:\n got %v\nwant %v", ids, sorted)
		}
	}
}

func TestNewEventIDIsUniqueWithinOneClockTick(t *testing.T) {
	t.Parallel()

	clock := domain.NewFixedClock(time.Date(2026, time.October, 23, 9, 0, 0, 0, time.UTC))
	seen := make(map[domain.EventID]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		id, err := domain.NewEventID(clock)
		if err != nil {
			t.Fatalf("NewEventID: %v", err)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("NewEventID returned %q twice within one clock tick", id)
		}
		seen[id] = struct{}{}
	}
}

func TestParseEventIDRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"empty":     "",
		"too_short": "0193a1b2",
		"too_long":  strings.Repeat("0", 33),
		"not_hex":   strings.Repeat("g", 32),
		"uppercase": strings.Repeat("A", 32),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := domain.ParseEventID(in); !errors.Is(err, domain.ErrMalformedEventID) {
				t.Fatalf("ParseEventID(%q) error = %v, want ErrMalformedEventID", in, err)
			}
		})
	}
}

func TestRecordValidate(t *testing.T) {
	t.Parallel()

	valid := domain.Record{
		Actor:   "principal-1",
		Subject: domain.SubjectRef{Kind: "document", ID: "doc-1"},
		Action:  "content.read",
		Outcome: "allowed",
		Detail:  []byte(`{"bytes":1}`),
	}

	cases := []struct {
		name    string
		mutate  func(r *domain.Record)
		wantErr bool
	}{
		{"valid", func(*domain.Record) {}, false},
		{"no_subject_is_allowed", func(r *domain.Record) { r.Subject = domain.SubjectRef{} }, false},
		{"no_detail_is_allowed", func(r *domain.Record) { r.Detail = nil }, false},
		{"empty_actor", func(r *domain.Record) { r.Actor = "" }, true},
		{"empty_action", func(r *domain.Record) { r.Action = "" }, true},
		{"empty_outcome", func(r *domain.Record) { r.Outcome = "" }, true},
		{"subject_kind_without_id", func(r *domain.Record) { r.Subject = domain.SubjectRef{Kind: "document"} }, true},
		{"subject_id_without_kind", func(r *domain.Record) { r.Subject = domain.SubjectRef{ID: "doc-1"} }, true},
		{"actor_too_long", func(r *domain.Record) { r.Actor = domain.ActorID(strings.Repeat("a", 1024)) }, true},
		{"action_too_long", func(r *domain.Record) { r.Action = domain.Action(strings.Repeat("a", 1024)) }, true},
		{"outcome_too_long", func(r *domain.Record) { r.Outcome = domain.Outcome(strings.Repeat("a", 1024)) }, true},
		{"subject_kind_too_long", func(r *domain.Record) { r.Subject.Kind = strings.Repeat("a", 1024) }, true},
		{"subject_id_too_long", func(r *domain.Record) { r.Subject.ID = strings.Repeat("a", 1024) }, true},
		{"detail_too_large", func(r *domain.Record) { r.Detail = make([]byte, domain.MaxDetailLen+1) }, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := valid.Clone()
			tc.mutate(&rec)

			err := rec.Validate()
			if tc.wantErr && !errors.Is(err, domain.ErrInvalidRecord) {
				t.Fatalf("Validate error = %v, want ErrInvalidRecord", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}

// TestRecordValidateDoesNotQuoteDetail is the module-wide no-leak invariant
// at its only validation boundary: an audit detail payload may carry
// sensitive content, so no error may reproduce it. See the package doc.
func TestRecordValidateDoesNotQuoteDetail(t *testing.T) {
	t.Parallel()

	const sentinel = "sentinel-7c1f4a-do-not-leak-this-value"
	rec := domain.Record{
		Actor:   "principal-1",
		Action:  "content.read",
		Outcome: "allowed",
		Detail:  append([]byte(sentinel), make([]byte, domain.MaxDetailLen)...),
	}

	err := rec.Validate()
	if err == nil {
		t.Fatal("an oversized detail payload was accepted")
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Fatalf("Validate error leaked detail content: %v", err)
	}
}

func TestRecordCloneDoesNotShareDetail(t *testing.T) {
	t.Parallel()

	original := domain.Record{Detail: []byte("abc")}
	clone := original.Clone()
	clone.Detail[0] = 'X'
	if original.Detail[0] == 'X' {
		t.Fatal("Clone shares the Detail backing array with the original")
	}
}
