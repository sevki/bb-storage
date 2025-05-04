package starlarkutil

import (
	"go.starlark.net/starlark"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Empty emptypb.Empty

func ToEmpty(e *emptypb.Empty) Empty { return Empty(*e) }

func (Empty) ToStarlark() starlark.Value { return starlark.None }

// String returns the string representation of the value.
// Starlark string values are quoted as if by Python's repr.
func (Empty) String() string { return starlark.None.String() }

// Type returns a short string describing the value's type.
func (Empty) Type() string { return starlark.None.Type() }

// Freeze causes the value, and all values transitively
// reachable from it through collections and closures, to be
// marked as frozen.  All subsequent mutations to the data
// structure through this API will fail dynamically, making the
// data structure immutable and safe for publishing to other
// Starlark interpreters running concurrently.
func (Empty) Freeze() {}

// Truth returns the truth value of an object.
func (Empty) Truth() starlark.Bool { return starlark.None.Truth() }

// Hash returns a function of x such that Equals(x, y) => Hash(x) == Hash(y).
// Hash may fail if the value's type is not hashable, or if the value
// contains a non-hashable value. The hash is used only by dictionaries and
// is not exposed to the Starlark program.
func (Empty) Hash() (uint32, error) { return starlark.None.Hash() }
