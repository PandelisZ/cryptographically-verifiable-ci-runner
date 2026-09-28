// Package a is pure: its test depends on nothing but its own code.
package a

// Add returns x + y.
func Add(x, y int) int { return x + y }
