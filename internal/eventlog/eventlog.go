// Package eventlog defines the append-only, hash-chained event log that is
// the whole of this module: eventlog.Log moves audit entries in one
// direction only, and Verify re-derives the chain over them so that a
// reader can tell whether what came back is what was written. It holds no
// opinion about what an event means — Action, Outcome, Actor and Detail are
// opaque to it (see internal/domain) — and none about who may read it,
// which is an iam permission and not a property of a log.
//
// Every adapter — the in-memory one in this package, and the Postgres one
// a later increment adds — must pass audittest.RunLogSuite unchanged;
// that suite, not this file, is the authoritative description of the
// contract's edge-case behaviour. It lives in a sibling package so that a
// consumer can run it against its own wiring without this package
// dragging testing into every consumer's production import graph.
//
// # Why Verify is a function and not a method
//
// Verification lives here, in one implementation over the port, rather
// than as a Log method each adapter supplies. An adapter that verified
// itself would be asked to attest to its own integrity, and the first
// thing an attacker with write access to the store does is make that
// attestation say yes. Because Verify only reads entries back through the
// port, the same code verifies a live Postgres log, an in-memory one, and
// a chain exported to a file and re-read somewhere else entirely
// (VerifyEntries). That is what "independently verified" in CHARTER.md
// has to mean to be worth anything.
//
// # No event content in errors
//
// A Detail payload may carry sensitive material, and a verifier runs over
// material that is, by hypothesis, under an attacker's influence. No error
// from this package reproduces any of it: a verification failure names a
// break kind and a sequence number and nothing else. See audittest's
// NoEventDetailLeaksInErrors subtest, which every adapter exercises.
package eventlog

import (
	"context"
	"fmt"

	"github.com/laenenai/audit/internal/domain"
)

// defaultPageSize is how many entries Verify reads per call when
// VerifyOptions.PageSize is zero. It is large enough that verifying a
// million-entry chain is a thousand round trips rather than a million, and
// small enough that a page is a few megabytes at the Detail size limit
// rather than an unbounded result set.
const defaultPageSize = 1000

// Log is the port every audit log adapter implements: an append-only
// sequence of entries, each committing to its predecessor.
//
// There is no Update, no Delete and no Truncate, and that is the point —
// the interface offers no way to express the operations Verify exists to
// detect. An adapter's storage will of course permit them (a DELETE
// statement does not ask); what the port guarantees is that nothing
// reaching for this module can perform one.
//
// # Participating in a caller's transaction
//
// An audit record and the thing it describes should commit together or not
// at all: a grant recorded but not performed is confusing, and a grant
// performed but not recorded is the failure mode the log exists to
// prevent. The shape above permits that, and the reasoning is worth
// stating because it constrains adapters:
//
//   - Append is a single call that both reads the chain head and writes
//     the new entry. The adapter owns that read-modify-write entirely;
//     nothing in this package reads a head and hands it back for a later
//     append, and nothing caches a head between calls. So an adapter is
//     free to perform both halves inside whatever transaction it was
//     given, and a caller can never hold a head that a rolled-back
//     transaction invalidated.
//   - Every method takes a context.Context as its first argument, which
//     is where a SQL adapter picks up the caller's transaction — the
//     caller puts its *sql.Tx (or pgx.Tx) in the context with that
//     adapter's own key and the adapter uses it instead of its pool. The
//     port therefore needs no database/sql in its signatures and this
//     module needs no SQL dependency at all.
//
// The honest cost of the context mechanism is that enlistment is invisible
// to the type system: a caller who forgets to put the transaction in the
// context gets a correct-looking append that commits independently. The
// alternative — a WithTx(any) (Log, error) method on the port — makes it
// visible but puts an `any` in the public API of a module that has no
// transactional adapter yet. This increment ships neither; it ships a port
// that does not foreclose either, and the Postgres increment picks one
// with a real adapter in front of it. What matters is that the choice is
// still open, which it would not be if Append required the caller to
// supply the previous digest.
//
// A second constraint follows for any adapter whose storage is shared:
// because the new entry's digest depends on the current head's, the
// head-read and the insert must be serialized against other appenders —
// a row lock on a per-chain head row, or a unique constraint on the
// sequence number plus a retry. Two appenders that both read head N
// produce two entries claiming sequence N+1, and one of them must lose.
// ConcurrentAppendsProduceOneWellOrderedChain in audittest is that
// requirement as a test.
type Log interface {
	// Append records rec as the next entry in the chain and returns the
	// entry it wrote, including the id, sequence, timestamp and link the
	// log assigned. A caller cannot choose any of those.
	//
	// Append validates rec (see domain.Record.Validate) and returns a
	// wrapped domain.ErrInvalidRecord without consuming a sequence
	// number if it does not pass, so a rejected append leaves the chain
	// exactly as it was.
	//
	// rec.Detail is copied, not retained: the caller may reuse its
	// buffer immediately. Likewise the returned entry shares no memory
	// with what the log holds.
	Append(ctx context.Context, rec domain.Record) (domain.Entry, error)

	// Head returns the chain's current end: the sequence and digest of
	// the most recently appended entry, or the zero domain.Checkpoint if
	// nothing has been appended. An empty log is not an error.
	//
	// The returned checkpoint is what a caller keeps in order to detect a
	// later truncation — see Verify.
	Head(ctx context.Context) (domain.Checkpoint, error)

	// Entries returns up to limit entries with sequence >= from, in
	// ascending sequence order with no gaps. A from past the end of the
	// chain returns no entries and no error; from == 0 is equivalent to
	// from == domain.FirstSequence, since no entry has sequence 0.
	//
	// limit must be positive: a non-positive limit is a wrapped
	// domain.ErrInvalidArgument, not an empty page, because "zero means
	// unlimited" and "zero means none" are both plausible and silently
	// returning either would make a paging loop wrong in a way that only
	// shows up at scale.
	//
	// A short page (fewer than limit entries) means the end of the chain
	// has been reached. The returned entries share no memory with what
	// the log holds.
	Entries(ctx context.Context, from uint64, limit int) ([]domain.Entry, error)
}

// VerifyOptions configures a verification pass. The zero value is valid
// and means "verify the chain's whole internal consistency from its genesis
// entry, with no external witness and the default page size".
type VerifyOptions struct {
	// Root is where verification begins: the chain is walked from the
	// entry after Root, and that entry's Prev must be Root's digest. The
	// zero Checkpoint means "from the genesis entry", which is the only
	// correct default for a chain that has never been truncated.
	//
	// It exists because retention and tamper-evidence are only compatible
	// through checkpoints. You cannot delete from a hash chain without
	// breaking verification from the genesis, so retention drops whole
	// partitions at a checkpoint boundary and the checkpoint becomes the
	// chain's new verification root: the entries before it are genuinely
	// gone, and a verifier walking from sequence one would report the hole
	// as tampering rather than as the retention it is.
	//
	// What a root costs, and it is not free: everything at or before Root
	// is accepted on Root's authority alone. A Root a caller invented, or
	// read back out of the same storage that holds the chain, proves
	// nothing — it would let whoever controls the storage declare any
	// prefix to be history. A root is only worth what its provenance is
	// worth, which is why a published, signed checkpoint stops being a
	// security nicety and becomes a functional prerequisite for retention.
	// This module does not yet publish one; until it does, a Root must come
	// from somewhere the log's operator does not control.
	//
	// Root and Witness are independent and compose. Root says where the
	// verifier may begin; Witness says what must still be present. A
	// Witness behind Root names an entry retention removed, so it reports
	// BreakTruncated — the chain genuinely cannot show it.
	Root domain.Checkpoint

	// Witness is a checkpoint the caller previously obtained from this
	// chain and has reason to trust — because it was recorded elsewhere,
	// published, countersigned, or simply kept by a party that does not
	// also control the log's storage.
	//
	// The zero Checkpoint means "no witness", which is a strictly weaker
	// verification: see Verify's doc comment for exactly what is lost.
	Witness domain.Checkpoint

	// PageSize is how many entries Verify reads per call. Zero means
	// defaultPageSize. It affects only how the chain is read, never the
	// verdict: every page size produces the same result for the same
	// chain.
	PageSize int
}

// Verify walks log from its genesis entry to its end, re-deriving the hash
// chain, and returns the head it arrived at. A nil error means every entry
// the log returned is exactly the entry that was appended, in exactly the
// position it was appended to.
//
// # What it proves
//
// Each entry's digest commits to all of its own fields and to its
// predecessor's digest, and each entry's position is one of the fields
// committed to. So:
//
//   - A modified entry — any field, including the timestamp and the
//     detail payload — no longer hashes to its stored digest.
//     (domain.BreakDigestMismatch.)
//   - A modified entry whose digest was also recomputed breaks its
//     successor's Prev instead. (domain.BreakLinkMismatch.) The same
//     applies to an entry spliced in from a different chain.
//   - A deleted entry leaves a gap in a sequence that must be
//     contiguous from domain.FirstSequence.
//     (domain.BreakSequenceMismatch.)
//   - A reordered pair of entries puts a sequence number where the chain
//     required a different one. (domain.BreakSequenceMismatch, the same
//     kind as a deletion — a chain detects both by the same mechanism,
//     because an entry's claimed position is part of what its digest
//     commits to, and the kinds do not pretend to more precision than
//     that.)
//   - A log whose own reported Head is not the end of the chain it
//     served. (domain.BreakHeadMismatch.) An adapter like that is not
//     necessarily under attack, but it is one whose truncation could not
//     be detected, which is a verification failure either way.
//
// Every one of those is reported as a *domain.ChainError wrapping
// domain.ErrChainBroken.
//
// # What it cannot prove, and the one case that needs a witness
//
// Truncation of the tail is categorically different from everything
// above, and no amount of hashing fixes it: a prefix of a valid chain is
// itself a valid chain. If the last k entries are removed, what remains
// verifies clean, because every entry still commits to its real
// predecessor and the sequence is still contiguous from the genesis. The
// log cannot bear witness to its own completeness — asking it to would be
// asking it to prove the existence of something it no longer holds.
//
// Detection therefore requires something the log's holder does not
// control. Verify's mechanism is VerifyOptions.Witness: a checkpoint the
// caller obtained earlier and kept. Given one, Verify additionally proves
//
//   - that the chain still reaches the witnessed sequence
//     (domain.BreakTruncated otherwise), and
//   - that the entry at that sequence is still the exact entry that was
//     witnessed (domain.BreakCheckpointMismatch otherwise), which also
//     catches the stronger attack of replacing a whole suffix with a
//     different but internally consistent one.
//
// Together those two mean: nothing at or before the witnessed sequence has
// been altered, removed, or reordered, and the log has not regressed
// behind it.
//
// What a witness still does not prove:
//
//   - That entries appended after the witness and then removed ever
//     existed. The window of deniability is exactly "everything since the
//     last witness", so the frequency with which checkpoints are taken
//     and published somewhere the log's operator does not control is the
//     real security parameter — not anything in this package.
//   - That an append that never reached the log was attempted. A log
//     records what it was told; a caller that drops an audit write before
//     calling Append leaves no trace, which is why an audit append
//     belongs in the same transaction as the thing it describes (see
//     Log).
//   - That the timestamps are truthful. They are the log's own clock,
//     committed to by the chain, so they cannot be changed after the
//     fact — but a log whose clock was wrong when it appended records a
//     wrong time, verifiably.
//   - Anything about a chain that was never witnessed at all. A log
//     created, written, and truncated between two checkpoints is
//     indistinguishable from a log that was never written to.
//
// A caller obtains a witness from Head or from a previous Verify, and the
// value of one is entirely in where it is kept.
//
// # Verifying a chain that retention has truncated from the front
//
// A chain whose oldest entries have been dropped on purpose — retention
// drops whole partitions at a checkpoint boundary — no longer starts at its
// genesis, and verifying it from sequence one reports the missing prefix as
// tampering. VerifyOptions.Root is how a caller says "this checkpoint is
// where this chain now begins"; see its documentation for what that costs,
// which is that everything at or before the root is taken on the root's
// authority and a root is therefore only worth its provenance.
func Verify(ctx context.Context, log Log, opt VerifyOptions) (domain.Checkpoint, error) {
	pageSize := opt.PageSize
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}

	w := newWalker(opt.Root, opt.Witness)
	for from := w.want; ; {
		page, err := log.Entries(ctx, from, pageSize)
		if err != nil {
			return domain.Checkpoint{}, fmt.Errorf("audit: verify: read entries from sequence %d: %w", from, err)
		}
		if len(page) == 0 {
			break
		}
		for _, entry := range page {
			if err := w.push(entry); err != nil {
				return domain.Checkpoint{}, err
			}
		}
		if len(page) < pageSize {
			break
		}
		from = w.want
	}

	head, err := w.finish()
	if err != nil {
		return domain.Checkpoint{}, err
	}

	reported, err := log.Head(ctx)
	if err != nil {
		return domain.Checkpoint{}, fmt.Errorf("audit: verify: read head: %w", err)
	}
	if reported.Sequence != head.Sequence || !reported.Digest.Equal(head.Digest) {
		return domain.Checkpoint{}, domain.NewChainError(domain.BreakHeadMismatch, head.Sequence)
	}
	return head, nil
}

// VerifyEntries applies exactly the rules Verify applies, to a chain
// already in memory: a page a caller read itself, or a chain exported to a
// file and verified on a machine that has no access to the log at all.
// entries must begin at the chain's genesis and be in ascending sequence
// order.
//
// It performs no head-agreement check, there being no log to ask. Verify's
// doc comment is the contract; this is the same walk without the I/O.
func VerifyEntries(entries []domain.Entry, opt VerifyOptions) (domain.Checkpoint, error) {
	w := newWalker(opt.Root, opt.Witness)
	for _, entry := range entries {
		if err := w.push(entry); err != nil {
			return domain.Checkpoint{}, err
		}
	}
	return w.finish()
}

// walker is the streaming chain verifier both Verify and VerifyEntries are
// built from. It holds only the running state a chain walk needs — the
// previous digest, the next required sequence, and whether the witness has
// been seen — so verifying a chain of any length costs constant memory.
type walker struct {
	witness     domain.Checkpoint
	witnessSeen bool

	prev domain.Digest
	want uint64
	head domain.Checkpoint
}

// newWalker starts a walk after root — which is the zero Checkpoint for an
// untruncated chain, and then prev is the genesis entry's zero predecessor
// and want is domain.FirstSequence, exactly as before roots existed.
//
// head starts at root rather than at the zero Checkpoint so that walking no
// entries at all from a non-zero root reports the root as the head: a chain
// whose entire surviving tail is empty is at its root, not empty.
func newWalker(root, witness domain.Checkpoint) *walker {
	want := domain.FirstSequence
	if !root.IsZero() {
		want = root.Sequence + 1
	}
	return &walker{
		witness: witness,
		prev:    root.Digest,
		want:    want,
		head:    root,
	}
}

// push verifies one entry as the successor of everything pushed so far.
// The checks are ordered from the most specific attribution to the least:
// a wrong position is reported as a sequence break even though it would
// also have produced a link break, because "the entry that should be at
// sequence 3 is not" localizes the damage better than "entry 4's
// predecessor is wrong".
func (w *walker) push(entry domain.Entry) error {
	if entry.Event.Sequence != w.want {
		return domain.NewChainError(domain.BreakSequenceMismatch, w.want)
	}
	if !entry.Link.Prev.Equal(w.prev) {
		return domain.NewChainError(domain.BreakLinkMismatch, entry.Event.Sequence)
	}
	if !entry.ComputeDigest().Equal(entry.Link.Self) {
		return domain.NewChainError(domain.BreakDigestMismatch, entry.Event.Sequence)
	}

	if !w.witness.IsZero() && entry.Event.Sequence == w.witness.Sequence {
		if !entry.Link.Self.Equal(w.witness.Digest) {
			return domain.NewChainError(domain.BreakCheckpointMismatch, w.witness.Sequence)
		}
		w.witnessSeen = true
	}

	w.prev = entry.Link.Self
	w.want++
	w.head = domain.Checkpoint{Sequence: entry.Event.Sequence, Digest: entry.Link.Self}
	return nil
}

// finish reports the head the walk reached, after the one check that can
// only be made at the end: a witnessed sequence the chain never reached is
// a truncated tail. Note that this is also the verdict when the witness is
// ahead of the chain for an innocent reason — a caller that mixed up two
// logs' checkpoints, say. The verifier cannot tell those apart, and
// treating an unmet witness as anything other than a failure would make
// the witness worthless.
func (w *walker) finish() (domain.Checkpoint, error) {
	if !w.witness.IsZero() && !w.witnessSeen {
		return domain.Checkpoint{}, domain.NewChainError(domain.BreakTruncated, w.witness.Sequence)
	}
	return w.head, nil
}
