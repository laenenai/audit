package domain

// ExportEntryDomainTag exposes entryDomainTag to this package's external
// tests. The tag is a cryptographic input to every entry digest, and
// TestEntryDomainTagIsPinned asserts its exact value so that a change to it
// reports itself by name rather than as two mismatched digests.
const ExportEntryDomainTag = entryDomainTag
