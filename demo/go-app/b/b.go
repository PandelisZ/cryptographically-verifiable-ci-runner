// Package b turns a greeting into a shout.
package b

import "example.com/abcd/internal/text"

// Greet shouts the greeting.
func Greet(greeting string) string { return text.Shout(greeting) }
