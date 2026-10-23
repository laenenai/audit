package migrate

import (
	"fmt"
	"time"

	"github.com/laenenai/audit/internal/domain"
)

// DefaultHashPartitions is how many hash partitions audit.event gets unless
// a deployment says otherwise: 64, which is the number CAS's design settled
// on for its own high-volume tenant-scoped tables, audit events included.
// Matching it is deliberate — these tables sit in the same database, and two
// different moduli over the same tenant ids would make a tenant's rows land
// in differently-shaped groups in different schemas for no reason anybody
// could later explain.
const DefaultHashPartitions = 64

// DefaultMonthsAhead and DefaultMonthsBehind are the range-partition window
// Up maintains inside each hash partition, relative to the month it runs in.
//
// Twelve months ahead because the migration is applied by the library at
// startup, so the window is extended by every deployment and restart, and a
// year of headroom means a process that is never restarted still has
// somewhere to write for a year. One month behind because a deployment
// migrating just after midnight on the first may still be writing entries
// that belong to the month that just ended.
const (
	DefaultMonthsAhead  = 12
	DefaultMonthsBehind = 1
)

// Config configures Up. The AppRole field is required; everything else has a
// default that a deployment has no reason to change unless it has a reason.
type Config struct {
	// AppRole is the name of the Postgres role the application runs as at
	// runtime — the role that must hold INSERT and SELECT on the history
	// and must not hold UPDATE, DELETE or TRUNCATE. Required.
	//
	// It is configuration rather than a constant because the migration has
	// to name it in its REVOKE, and the role is the deployment's to name:
	// one consumer's audit tables are reached by a role called after that
	// consumer, not after this module. Up creates the role if it does not
	// exist, as NOLOGIN — nothing connects as it directly; a session
	// reaches it through SET ROLE, which is what keeps the single-DSN
	// deployment model available.
	//
	// There is deliberately no default. A default would be a role name
	// nobody chose, which privilege separation would then appear to have
	// been applied to while the application connected as something else —
	// the exact failure this module is supposed to detect rather than
	// create.
	AppRole string

	// HashPartitions is how many hash partitions audit.event is divided
	// into. Zero means DefaultHashPartitions.
	//
	// It is fixed the first time Up runs and cannot be changed afterwards:
	// a different modulus redistributes every tenant, which is a data
	// migration and not a configuration edit. Up refuses a mismatch with
	// domain.ErrInvalidConfig rather than silently keeping the old value,
	// so a deployment that thinks it changed this finds out immediately.
	HashPartitions int

	// MonthsAhead and MonthsBehind size the range-partition window Up
	// maintains, in whole months either side of the month it runs in. Zero
	// means the DefaultMonthsAhead / DefaultMonthsBehind constants; a
	// negative value is a configuration error.
	MonthsAhead  int
	MonthsBehind int

	// Clock supplies "now" when deciding which months the window covers.
	// Nil means domain.SystemClock. A test that wants to create a partition
	// for a month in the past, so that it can then drop it, sets this.
	Clock domain.Clock
}

// resolvedConfig is Config with every default filled in, so nothing
// downstream of resolve has to remember which fields were optional.
type resolvedConfig struct {
	appRole        string
	hashPartitions int
	monthsAhead    int
	monthsBehind   int
	clock          domain.Clock
}

// resolve validates cfg and fills in its defaults.
func (c Config) resolve() (resolvedConfig, error) {
	out := resolvedConfig{
		appRole:        c.AppRole,
		hashPartitions: c.HashPartitions,
		monthsAhead:    c.MonthsAhead,
		monthsBehind:   c.MonthsBehind,
		clock:          c.Clock,
	}

	if out.appRole == "" {
		return resolvedConfig{}, fmt.Errorf("%w: migrate: AppRole is required: it is the role the REVOKE names, and there is no sensible default for it", domain.ErrInvalidConfig)
	}
	if !isPlainIdentifier(out.appRole) {
		return resolvedConfig{}, fmt.Errorf("%w: migrate: AppRole %q is not a plain identifier: letters, digits and underscore, not starting with a digit", domain.ErrInvalidConfig, out.appRole)
	}

	if out.hashPartitions == 0 {
		out.hashPartitions = DefaultHashPartitions
	}
	if out.hashPartitions < 1 {
		return resolvedConfig{}, fmt.Errorf("%w: migrate: HashPartitions is %d, want a positive count", domain.ErrInvalidConfig, out.hashPartitions)
	}

	if out.monthsAhead == 0 {
		out.monthsAhead = DefaultMonthsAhead
	}
	if out.monthsBehind == 0 {
		out.monthsBehind = DefaultMonthsBehind
	}
	if out.monthsAhead < 0 || out.monthsBehind < 0 {
		return resolvedConfig{}, fmt.Errorf("%w: migrate: MonthsAhead (%d) and MonthsBehind (%d) must not be negative", domain.ErrInvalidConfig, out.monthsAhead, out.monthsBehind)
	}

	if out.clock == nil {
		out.clock = domain.SystemClock{}
	}
	return out, nil
}

// now returns the instant the window is sized around, in UTC. UTC rather
// than local time because a partition boundary that moved with the server's
// time zone would put the same instant in two different partitions on two
// different machines.
func (c resolvedConfig) now() time.Time { return c.clock.Now().UTC() }

// isPlainIdentifier reports whether s is safe to use as an unquoted-shaped
// SQL identifier: ASCII letters, digits and underscore, not starting with a
// digit, and not empty.
//
// Every identifier this package interpolates is also run through
// pgx.Identifier.Sanitize, which quotes and escapes it; this check is a
// second, narrower gate in front of that, applied only to the one identifier
// that comes from configuration. GRANT and REVOKE cannot take a role name as
// a bound parameter, so the role name is the one value in this package that
// has to reach Postgres as SQL text, and a value in that position gets more
// than one reason to be safe.
func isPlainIdentifier(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		case c >= '0' && c <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return len(s) > 0
}
