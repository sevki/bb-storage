package starlarkutil

import (
	"fmt"

	"go.starlark.net/starlark"
	"google.golang.org/genproto/googleapis/rpc/status"
)

type Status struct{ *status.Status }

func ToStatus(s *status.Status) *Status { return &Status{s} }

// String returns the string representation of the value.
// Starlark string values are quoted as if by Python's repr.
func (s *Status) String() string {
	return fmt.Sprint("<google.rpc.Status %d %q>", s.GetCode(), s.GetMessage())
}

// Type returns a short string describing the value's type.
func (s *Status) Type() string { return "google.rpc.Status" }

// Freeze causes the value, and all values transitively
// reachable from it through collections and closures, to be
// marked as frozen.  All subsequent mutations to the data
// structure through this API will fail dynamically, making the
// data structure immutable and safe for publishing to other
// Starlark interpreters running concurrently.
func (s *Status) Freeze() {}

// Truth returns the truth value of an object.
func (s *Status) Truth() starlark.Bool { return s.Status != nil }

// Hash returns a function of x such that Equals(x, y) => Hash(x) == Hash(y).
// Hash may fail if the value's type is not hashable, or if the value
// contains a non-hashable value. The hash is used only by dictionaries and
// is not exposed to the Starlark program.
func (s *Status) Hash() (uint32, error) { return uint32(s.Code), nil }
