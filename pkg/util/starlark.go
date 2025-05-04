package util

import (
	"fmt"
	"log"

	"github.com/buildbarn/bb-storage/pkg/proto/configuration"

	"go.starlark.net/starlark"
)

func Unmarshal(path string, src interface{}) error {
	// Execute the Starlark file.
	thread := &starlark.Thread{
		Print: func(_ *starlark.Thread, msg string) { fmt.Println(msg) },
	}

	predeclared := starlark.StringDict{
		"conf": configuration.Module,
	}
	globals, err := starlark.ExecFile(thread, path, src, predeclared)
	if err != nil {
		if evalErr, ok := err.(*starlark.EvalError); ok {
			return fmt.Errorf("%s", evalErr.Backtrace())
		} else {
			return fmt.Errorf("%s", err)
		}
	}
	log.Println(globals)
	return nil
}
