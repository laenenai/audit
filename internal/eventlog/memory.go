package eventlog

import (
	"context"
	"fmt"
	"sync"

	"github.com/laenen-ai/audit/internal/domain"
)

// memoryLog is the in-memory Log adapter: a slice of entries behind a
// mutex. It is the adapter the core is unit-tested against, and the
// reference an adapter author reads to see what the suite actually
// demands; it is not a production store, since nothing here survives the
// process.
//
// The mutex is held across the whole of Append — the clock read, the
// sequence assignment, and the link computation — rather than only across
// the slice write. That is not caution about the slice; it is the
// serialization the chain requires. Two appenders that both observed the
// same head would compute two entries claiming the same sequence and the
// same predecessor, and one of them would have to be thrown away. A SQL
// adapter faces exactly this and solves it the same way, with a row lock
// or a unique constraint plus a retry rather than a process-local mutex.
//
// Holding the lock across the clock read is also what lets a caller pass
// a domain.FixedClock, which is not itself safe for concurrent use, to a
// log under concurrent appends.
type memoryLog struct {
	clock domain.Clock

	mu      sync.Mutex
	entries []domain.Entry
	head    domain.Checkpoint
}

var _ Log = (*memoryLog)(nil)

// MemoryConfig configures NewMemory. The zero value is valid.
type MemoryConfig struct {
	// Clock supplies the instant each appended entry records. Nil means
	// domain.SystemClock. A domain.FixedClock is safe here even under
	// concurrent appends — see memoryLog.
	Clock domain.Clock
}

// NewMemory returns an in-memory Log. It cannot fail, so it returns no
// error: there is no resource to acquire and nothing in MemoryConfig that
// can be invalid.
func NewMemory(cfg MemoryConfig) Log {
	clock := cfg.Clock
	if clock == nil {
		clock = domain.SystemClock{}
	}
	return &memoryLog{clock: clock}
}

// Append implements Log.
func (l *memoryLog) Append(ctx context.Context, rec domain.Record) (domain.Entry, error) {
	if err := ctx.Err(); err != nil {
		return domain.Entry{}, fmt.Errorf("audit: append: %w", err)
	}
	// Validated before the lock is taken and before anything is
	// assigned, so a rejected record never consumes a sequence number.
	if err := rec.Validate(); err != nil {
		return domain.Entry{}, fmt.Errorf("audit: append: %w", err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	id, err := domain.NewEventID(l.clock)
	if err != nil {
		return domain.Entry{}, fmt.Errorf("audit: append: %w", err)
	}

	sequence := l.head.Sequence + 1
	entry := domain.NewEntry(l.head.Digest, domain.NewEvent(id, sequence, l.clock.Now(), rec))

	l.entries = append(l.entries, entry)
	l.head = domain.Checkpoint{Sequence: entry.Event.Sequence, Digest: entry.Link.Self}

	// The caller gets a copy: it must not be able to reach the stored
	// entry's Detail bytes and make the chain disagree with itself.
	return entry.Clone(), nil
}

// Head implements Log.
func (l *memoryLog) Head(ctx context.Context) (domain.Checkpoint, error) {
	if err := ctx.Err(); err != nil {
		return domain.Checkpoint{}, fmt.Errorf("audit: head: %w", err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	return l.head, nil
}

// Entries implements Log. Because sequences are dense and start at
// domain.FirstSequence, the page is a slice offset rather than a scan.
func (l *memoryLog) Entries(ctx context.Context, from uint64, limit int) ([]domain.Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("audit: entries: %w", err)
	}
	if limit <= 0 {
		return nil, fmt.Errorf("audit: entries: %w: limit is %d, want a positive page size", domain.ErrInvalidArgument, limit)
	}
	if from < domain.FirstSequence {
		from = domain.FirstSequence
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	start := from - domain.FirstSequence
	if start >= uint64(len(l.entries)) {
		return nil, nil
	}
	page := l.entries[start:]
	if len(page) > limit {
		page = page[:limit]
	}

	out := make([]domain.Entry, 0, len(page))
	for _, entry := range page {
		out = append(out, entry.Clone())
	}
	return out, nil
}
