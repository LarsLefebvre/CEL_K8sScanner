// Package policies embeds the built-in policy library into the kscan binary.
package policies

import "embed"

//go:embed *.yaml
var Builtin embed.FS
