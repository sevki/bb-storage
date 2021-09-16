// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.17.3
// source: pkg/proto/configuration/spiffe/spiffe.proto

package spiffe

import (
	reflect "reflect"
	sync "sync"

	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Configuration struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Svid           string            `protobuf:"bytes,1,opt,name=svid,proto3" json:"svid,omitempty"`
	Key            string            `protobuf:"bytes,2,opt,name=key,proto3" json:"key,omitempty"`
	CaCertificates map[string]string `protobuf:"bytes,3,rep,name=ca_certificates,json=caCertificates,proto3" json:"ca_certificates,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *Configuration) Reset() {
	*x = Configuration{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_proto_configuration_spiffe_spiffe_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Configuration) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Configuration) ProtoMessage() {}

func (x *Configuration) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_proto_configuration_spiffe_spiffe_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Configuration.ProtoReflect.Descriptor instead.
func (*Configuration) Descriptor() ([]byte, []int) {
	return file_pkg_proto_configuration_spiffe_spiffe_proto_rawDescGZIP(), []int{0}
}

func (x *Configuration) GetSvid() string {
	if x != nil {
		return x.Svid
	}
	return ""
}

func (x *Configuration) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *Configuration) GetCaCertificates() map[string]string {
	if x != nil {
		return x.CaCertificates
	}
	return nil
}

type SubjectMatcher struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AllowedSpiffeIds map[string]string `protobuf:"bytes,10,rep,name=allowed_spiffe_ids,json=allowedSpiffeIds,proto3" json:"allowed_spiffe_ids,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *SubjectMatcher) Reset() {
	*x = SubjectMatcher{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_proto_configuration_spiffe_spiffe_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SubjectMatcher) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SubjectMatcher) ProtoMessage() {}

func (x *SubjectMatcher) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_proto_configuration_spiffe_spiffe_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SubjectMatcher.ProtoReflect.Descriptor instead.
func (*SubjectMatcher) Descriptor() ([]byte, []int) {
	return file_pkg_proto_configuration_spiffe_spiffe_proto_rawDescGZIP(), []int{1}
}

func (x *SubjectMatcher) GetAllowedSpiffeIds() map[string]string {
	if x != nil {
		return x.AllowedSpiffeIds
	}
	return nil
}

var File_pkg_proto_configuration_spiffe_spiffe_proto protoreflect.FileDescriptor

var file_pkg_proto_configuration_spiffe_spiffe_proto_rawDesc = []byte{
	0x0a, 0x2b, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x63, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x73, 0x70, 0x69, 0x66, 0x66, 0x65,
	0x2f, 0x73, 0x70, 0x69, 0x66, 0x66, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1e, 0x62,
	0x75, 0x69, 0x6c, 0x64, 0x62, 0x61, 0x72, 0x6e, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75,
	0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x73, 0x70, 0x69, 0x66, 0x66, 0x65, 0x22, 0xe4, 0x01,
	0x0a, 0x0d, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12,
	0x12, 0x0a, 0x04, 0x73, 0x76, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x73,
	0x76, 0x69, 0x64, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x6a, 0x0a, 0x0f, 0x63, 0x61, 0x5f, 0x63, 0x65, 0x72, 0x74,
	0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x41,
	0x2e, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x62, 0x61, 0x72, 0x6e, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x73, 0x70, 0x69, 0x66, 0x66, 0x65, 0x2e,
	0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x43, 0x61,
	0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x73, 0x45, 0x6e, 0x74, 0x72,
	0x79, 0x52, 0x0e, 0x63, 0x61, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65,
	0x73, 0x1a, 0x41, 0x0a, 0x13, 0x43, 0x61, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61,
	0x74, 0x65, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61,
	0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65,
	0x3a, 0x02, 0x38, 0x01, 0x22, 0xc9, 0x01, 0x0a, 0x0e, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74,
	0x4d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x12, 0x72, 0x0a, 0x12, 0x61, 0x6c, 0x6c, 0x6f, 0x77,
	0x65, 0x64, 0x5f, 0x73, 0x70, 0x69, 0x66, 0x66, 0x65, 0x5f, 0x69, 0x64, 0x73, 0x18, 0x0a, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x44, 0x2e, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x62, 0x61, 0x72, 0x6e, 0x2e,
	0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x73, 0x70,
	0x69, 0x66, 0x66, 0x65, 0x2e, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4d, 0x61, 0x74, 0x63,
	0x68, 0x65, 0x72, 0x2e, 0x41, 0x6c, 0x6c, 0x6f, 0x77, 0x65, 0x64, 0x53, 0x70, 0x69, 0x66, 0x66,
	0x65, 0x49, 0x64, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x10, 0x61, 0x6c, 0x6c, 0x6f, 0x77,
	0x65, 0x64, 0x53, 0x70, 0x69, 0x66, 0x66, 0x65, 0x49, 0x64, 0x73, 0x1a, 0x43, 0x0a, 0x15, 0x41,
	0x6c, 0x6c, 0x6f, 0x77, 0x65, 0x64, 0x53, 0x70, 0x69, 0x66, 0x66, 0x65, 0x49, 0x64, 0x73, 0x45,
	0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01,
	0x42, 0x40, 0x5a, 0x3e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x62,
	0x75, 0x69, 0x6c, 0x64, 0x62, 0x61, 0x72, 0x6e, 0x2f, 0x62, 0x62, 0x2d, 0x73, 0x74, 0x6f, 0x72,
	0x61, 0x67, 0x65, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x63, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x73, 0x70, 0x69, 0x66,
	0x66, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_pkg_proto_configuration_spiffe_spiffe_proto_rawDescOnce sync.Once
	file_pkg_proto_configuration_spiffe_spiffe_proto_rawDescData = file_pkg_proto_configuration_spiffe_spiffe_proto_rawDesc
)

func file_pkg_proto_configuration_spiffe_spiffe_proto_rawDescGZIP() []byte {
	file_pkg_proto_configuration_spiffe_spiffe_proto_rawDescOnce.Do(func() {
		file_pkg_proto_configuration_spiffe_spiffe_proto_rawDescData = protoimpl.X.CompressGZIP(file_pkg_proto_configuration_spiffe_spiffe_proto_rawDescData)
	})
	return file_pkg_proto_configuration_spiffe_spiffe_proto_rawDescData
}

var (
	file_pkg_proto_configuration_spiffe_spiffe_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
	file_pkg_proto_configuration_spiffe_spiffe_proto_goTypes  = []interface{}{
		(*Configuration)(nil),  // 0: buildbarn.configuration.spiffe.Configuration
		(*SubjectMatcher)(nil), // 1: buildbarn.configuration.spiffe.SubjectMatcher
		nil,                    // 2: buildbarn.configuration.spiffe.Configuration.CaCertificatesEntry
		nil,                    // 3: buildbarn.configuration.spiffe.SubjectMatcher.AllowedSpiffeIdsEntry
	}
)

var file_pkg_proto_configuration_spiffe_spiffe_proto_depIdxs = []int32{
	2, // 0: buildbarn.configuration.spiffe.Configuration.ca_certificates:type_name -> buildbarn.configuration.spiffe.Configuration.CaCertificatesEntry
	3, // 1: buildbarn.configuration.spiffe.SubjectMatcher.allowed_spiffe_ids:type_name -> buildbarn.configuration.spiffe.SubjectMatcher.AllowedSpiffeIdsEntry
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_pkg_proto_configuration_spiffe_spiffe_proto_init() }
func file_pkg_proto_configuration_spiffe_spiffe_proto_init() {
	if File_pkg_proto_configuration_spiffe_spiffe_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_pkg_proto_configuration_spiffe_spiffe_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Configuration); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_proto_configuration_spiffe_spiffe_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SubjectMatcher); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_pkg_proto_configuration_spiffe_spiffe_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_pkg_proto_configuration_spiffe_spiffe_proto_goTypes,
		DependencyIndexes: file_pkg_proto_configuration_spiffe_spiffe_proto_depIdxs,
		MessageInfos:      file_pkg_proto_configuration_spiffe_spiffe_proto_msgTypes,
	}.Build()
	File_pkg_proto_configuration_spiffe_spiffe_proto = out.File
	file_pkg_proto_configuration_spiffe_spiffe_proto_rawDesc = nil
	file_pkg_proto_configuration_spiffe_spiffe_proto_goTypes = nil
	file_pkg_proto_configuration_spiffe_spiffe_proto_depIdxs = nil
}
