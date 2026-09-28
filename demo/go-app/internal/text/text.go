// Package text is a dependency of b only.
package text

import "strings"

// Shout upper-cases s and adds an exclamation mark.
func Shout(s string) string { return strings.ToUpper(s) + "!" }
