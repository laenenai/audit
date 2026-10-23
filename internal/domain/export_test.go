package domain

// This file is compiled only under `go test`, so nothing here is part of the
// module's public surface — which is why it, and not an ordinary file, is where
// an internal constant is exposed to an external test. The pattern matches
// cas/internal/crypto/export_test.go.

// ExportEntryDomainTag exposes entryDomainTag to this package's external
// tests. The tag is a cryptographic input to every entry digest, and
// TestEntryDomainTagIsPinned asserts its exact value so that a change to it
// reports itself by name rather than as two mismatched digests.
const ExportEntryDomainTag = entryDomainTag
