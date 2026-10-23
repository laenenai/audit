// Package migrations embeds this module's schema migrations into the
// binary, so a process applying them never depends on a SQL file existing on
// disk next to it: internal/migrate reads migration sources from FS, not the
// local filesystem. Embedding is a requirement of the deployment model this
// module is built for — a single binary, migrations applied by the library
// at startup — not a convenience.
package migrations

import "embed"

// FS holds every *.sql migration file embedded at build time.
//
//go:embed *.sql
var FS embed.FS
