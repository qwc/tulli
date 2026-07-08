// Package migrations embeds the goose SQL migrations so they can be applied from
// the binary (or tests) without shipping loose files. The schema of record is
// prototype-spec-v2.md §9.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
