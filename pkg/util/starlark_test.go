package util

import (
	"testing"

	"github.com/buildbarn/bb-storage/pkg/proto/configuration/bb_storage"
	"google.golang.org/protobuf/proto"
)

func TestUnmarshal(t *testing.T) {
	type args struct {
		path          string
		src           interface{}
		configuration proto.Message
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "maximum_message_size_bytes",
			args: args{
				path: "common.bzl",
				src: `
print(conf)
				`,
				configuration: &bb_storage.ApplicationConfiguration{},
			},
			wantErr: false,
		},
		{
			name: "singleField",
			args: args{
				path: "common.bzl",
				src: `
server = conf.new("grpc.ServerConfiguration")
print(server)
				`,
				configuration: &bb_storage.ApplicationConfiguration{},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Unmarshal(tt.args.path, tt.args.src); (err != nil) != tt.wantErr {
				t.Errorf("Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
