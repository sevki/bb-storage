package configuration

import (
	"fmt"
	"reflect"
	"strings"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

var types = make(map[string]reflect.Type)

var Module = &starlarkstruct.Module{
	Name: "conf",
	Members: starlark.StringDict{
		"new": starlark.NewBuiltin("conf.new", newconf),
	},
}

func Register(name string, v starlark.Value) {
	types[strings.TrimPrefix(name, "buildbarn.configuration.")] = reflect.TypeOf(v).Elem()
}

func newconf(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	typeName, ok := args[0].(starlark.String)
	if !ok {
		panic(fmt.Sprintf("%T", args[0]))
	}
	val := reflect.New(types[typeName.GoString()]).Interface()
	return val.(starlark.Value), nil
}
