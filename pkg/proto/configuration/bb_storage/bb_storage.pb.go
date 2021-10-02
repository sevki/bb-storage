// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.17.3
// source: pkg/proto/configuration/bb_storage/bb_storage.proto

package bb_storage

import (
	reflect "reflect"
	sync "sync"

	auth "github.com/buildbarn/bb-storage/pkg/proto/configuration/auth"
	blobstore "github.com/buildbarn/bb-storage/pkg/proto/configuration/blobstore"
	builder "github.com/buildbarn/bb-storage/pkg/proto/configuration/builder"
	global "github.com/buildbarn/bb-storage/pkg/proto/configuration/global"
	grpc "github.com/buildbarn/bb-storage/pkg/proto/configuration/grpc"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type ApplicationConfiguration struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Blobstore                                    *blobstore.BlobstoreConfiguration          `protobuf:"bytes,1,opt,name=blobstore,proto3" json:"blobstore,omitempty"`
	GrpcServers                                  []*grpc.ServerConfiguration                `protobuf:"bytes,4,rep,name=grpc_servers,json=grpcServers,proto3" json:"grpc_servers,omitempty"`
	Schedulers                                   map[string]*builder.SchedulerConfiguration `protobuf:"bytes,5,rep,name=schedulers,proto3" json:"schedulers,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	MaximumMessageSizeBytes                      int64                                      `protobuf:"varint,8,opt,name=maximum_message_size_bytes,json=maximumMessageSizeBytes,proto3" json:"maximum_message_size_bytes,omitempty"`
	Global                                       *global.Configuration                      `protobuf:"bytes,9,opt,name=global,proto3" json:"global,omitempty"`
	IndirectContentAddressableStorage            *blobstore.BlobAccessConfiguration         `protobuf:"bytes,10,opt,name=indirect_content_addressable_storage,json=indirectContentAddressableStorage,proto3" json:"indirect_content_addressable_storage,omitempty"`
	InitialSizeClassCache                        *blobstore.BlobAccessConfiguration         `protobuf:"bytes,11,opt,name=initial_size_class_cache,json=initialSizeClassCache,proto3" json:"initial_size_class_cache,omitempty"`
	ContentAddressableStorageAuthorizers         *ScannableAuthorizersConfiguration         `protobuf:"bytes,12,opt,name=content_addressable_storage_authorizers,json=contentAddressableStorageAuthorizers,proto3" json:"content_addressable_storage_authorizers,omitempty"`
	IndirectContentAddressableStorageAuthorizers *ScannableAuthorizersConfiguration         `protobuf:"bytes,13,opt,name=indirect_content_addressable_storage_authorizers,json=indirectContentAddressableStorageAuthorizers,proto3" json:"indirect_content_addressable_storage_authorizers,omitempty"`
	ActionCacheAuthorizers                       *NonScannableAuthorizersConfiguration      `protobuf:"bytes,14,opt,name=action_cache_authorizers,json=actionCacheAuthorizers,proto3" json:"action_cache_authorizers,omitempty"`
	InitialSizeClassCacheAuthorizers             *NonScannableAuthorizersConfiguration      `protobuf:"bytes,15,opt,name=initial_size_class_cache_authorizers,json=initialSizeClassCacheAuthorizers,proto3" json:"initial_size_class_cache_authorizers,omitempty"`
	ExecuteAuthorizer                            *auth.AuthorizerConfiguration              `protobuf:"bytes,16,opt,name=execute_authorizer,json=executeAuthorizer,proto3" json:"execute_authorizer,omitempty"`
}

func (x *ApplicationConfiguration) Reset() {
	*x = ApplicationConfiguration{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_proto_configuration_bb_storage_bb_storage_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ApplicationConfiguration) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ApplicationConfiguration) ProtoMessage() {}

func (x *ApplicationConfiguration) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_proto_configuration_bb_storage_bb_storage_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ApplicationConfiguration.ProtoReflect.Descriptor instead.
func (*ApplicationConfiguration) Descriptor() ([]byte, []int) {
	return file_pkg_proto_configuration_bb_storage_bb_storage_proto_rawDescGZIP(), []int{0}
}

func (x *ApplicationConfiguration) GetBlobstore() *blobstore.BlobstoreConfiguration {
	if x != nil {
		return x.Blobstore
	}
	return nil
}

func (x *ApplicationConfiguration) GetGrpcServers() []*grpc.ServerConfiguration {
	if x != nil {
		return x.GrpcServers
	}
	return nil
}

func (x *ApplicationConfiguration) GetSchedulers() map[string]*builder.SchedulerConfiguration {
	if x != nil {
		return x.Schedulers
	}
	return nil
}

func (x *ApplicationConfiguration) GetMaximumMessageSizeBytes() int64 {
	if x != nil {
		return x.MaximumMessageSizeBytes
	}
	return 0
}

func (x *ApplicationConfiguration) GetGlobal() *global.Configuration {
	if x != nil {
		return x.Global
	}
	return nil
}

func (x *ApplicationConfiguration) GetIndirectContentAddressableStorage() *blobstore.BlobAccessConfiguration {
	if x != nil {
		return x.IndirectContentAddressableStorage
	}
	return nil
}

func (x *ApplicationConfiguration) GetInitialSizeClassCache() *blobstore.BlobAccessConfiguration {
	if x != nil {
		return x.InitialSizeClassCache
	}
	return nil
}

func (x *ApplicationConfiguration) GetContentAddressableStorageAuthorizers() *ScannableAuthorizersConfiguration {
	if x != nil {
		return x.ContentAddressableStorageAuthorizers
	}
	return nil
}

func (x *ApplicationConfiguration) GetIndirectContentAddressableStorageAuthorizers() *ScannableAuthorizersConfiguration {
	if x != nil {
		return x.IndirectContentAddressableStorageAuthorizers
	}
	return nil
}

func (x *ApplicationConfiguration) GetActionCacheAuthorizers() *NonScannableAuthorizersConfiguration {
	if x != nil {
		return x.ActionCacheAuthorizers
	}
	return nil
}

func (x *ApplicationConfiguration) GetInitialSizeClassCacheAuthorizers() *NonScannableAuthorizersConfiguration {
	if x != nil {
		return x.InitialSizeClassCacheAuthorizers
	}
	return nil
}

func (x *ApplicationConfiguration) GetExecuteAuthorizer() *auth.AuthorizerConfiguration {
	if x != nil {
		return x.ExecuteAuthorizer
	}
	return nil
}

type NonScannableAuthorizersConfiguration struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Get *auth.AuthorizerConfiguration `protobuf:"bytes,1,opt,name=get,proto3" json:"get,omitempty"`
	Put *auth.AuthorizerConfiguration `protobuf:"bytes,2,opt,name=put,proto3" json:"put,omitempty"`
}

func (x *NonScannableAuthorizersConfiguration) Reset() {
	*x = NonScannableAuthorizersConfiguration{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_proto_configuration_bb_storage_bb_storage_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NonScannableAuthorizersConfiguration) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NonScannableAuthorizersConfiguration) ProtoMessage() {}

func (x *NonScannableAuthorizersConfiguration) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_proto_configuration_bb_storage_bb_storage_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NonScannableAuthorizersConfiguration.ProtoReflect.Descriptor instead.
func (*NonScannableAuthorizersConfiguration) Descriptor() ([]byte, []int) {
	return file_pkg_proto_configuration_bb_storage_bb_storage_proto_rawDescGZIP(), []int{1}
}

func (x *NonScannableAuthorizersConfiguration) GetGet() *auth.AuthorizerConfiguration {
	if x != nil {
		return x.Get
	}
	return nil
}

func (x *NonScannableAuthorizersConfiguration) GetPut() *auth.AuthorizerConfiguration {
	if x != nil {
		return x.Put
	}
	return nil
}

type ScannableAuthorizersConfiguration struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Get         *auth.AuthorizerConfiguration `protobuf:"bytes,1,opt,name=get,proto3" json:"get,omitempty"`
	Put         *auth.AuthorizerConfiguration `protobuf:"bytes,2,opt,name=put,proto3" json:"put,omitempty"`
	FindMissing *auth.AuthorizerConfiguration `protobuf:"bytes,3,opt,name=find_missing,json=findMissing,proto3" json:"find_missing,omitempty"`
}

func (x *ScannableAuthorizersConfiguration) Reset() {
	*x = ScannableAuthorizersConfiguration{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_proto_configuration_bb_storage_bb_storage_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ScannableAuthorizersConfiguration) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ScannableAuthorizersConfiguration) ProtoMessage() {}

func (x *ScannableAuthorizersConfiguration) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_proto_configuration_bb_storage_bb_storage_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ScannableAuthorizersConfiguration.ProtoReflect.Descriptor instead.
func (*ScannableAuthorizersConfiguration) Descriptor() ([]byte, []int) {
	return file_pkg_proto_configuration_bb_storage_bb_storage_proto_rawDescGZIP(), []int{2}
}

func (x *ScannableAuthorizersConfiguration) GetGet() *auth.AuthorizerConfiguration {
	if x != nil {
		return x.Get
	}
	return nil
}

func (x *ScannableAuthorizersConfiguration) GetPut() *auth.AuthorizerConfiguration {
	if x != nil {
		return x.Put
	}
	return nil
}

func (x *ScannableAuthorizersConfiguration) GetFindMissing() *auth.AuthorizerConfiguration {
	if x != nil {
		return x.FindMissing
	}
	return nil
}

var File_pkg_proto_configuration_bb_storage_bb_storage_proto protoreflect.FileDescriptor

var file_pkg_proto_configuration_bb_storage_bb_storage_proto_rawDesc = []byte{
	0x0a, 0x33, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x63, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x62, 0x62, 0x5f, 0x73, 0x74, 0x6f,
	0x72, 0x61, 0x67, 0x65, 0x2f, 0x62, 0x62, 0x5f, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x22, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x62, 0x61, 0x72, 0x6e,
	0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x62,
	0x62, 0x5f, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x1a, 0x27, 0x70, 0x6b, 0x67, 0x2f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x31, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x63, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x62, 0x6c, 0x6f, 0x62,
	0x73, 0x74, 0x6f, 0x72, 0x65, 0x2f, 0x62, 0x6c, 0x6f, 0x62, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2d, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x62,
	0x75, 0x69, 0x6c, 0x64, 0x65, 0x72, 0x2f, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x65, 0x72, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x2b, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f,
	0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x67, 0x6c,
	0x6f, 0x62, 0x61, 0x6c, 0x2f, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x27, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x2f,
	0x67, 0x72, 0x70, 0x63, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xa3, 0x0c, 0x0a, 0x18, 0x41,
	0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x57, 0x0a, 0x09, 0x62, 0x6c, 0x6f, 0x62, 0x73,
	0x74, 0x6f, 0x72, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x39, 0x2e, 0x62, 0x75, 0x69,
	0x6c, 0x64, 0x62, 0x61, 0x72, 0x6e, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x62, 0x6c, 0x6f, 0x62, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x42,
	0x6c, 0x6f, 0x62, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x09, 0x62, 0x6c, 0x6f, 0x62, 0x73, 0x74, 0x6f, 0x72, 0x65,
	0x12, 0x54, 0x0a, 0x0c, 0x67, 0x72, 0x70, 0x63, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73,
	0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x31, 0x2e, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x62, 0x61,
	0x72, 0x6e, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x2e, 0x67, 0x72, 0x70, 0x63, 0x2e, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x43, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0b, 0x67, 0x72, 0x70, 0x63, 0x53,
	0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x12, 0x6c, 0x0a, 0x0a, 0x73, 0x63, 0x68, 0x65, 0x64, 0x75,
	0x6c, 0x65, 0x72, 0x73, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x4c, 0x2e, 0x62, 0x75, 0x69,
	0x6c, 0x64, 0x62, 0x61, 0x72, 0x6e, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x62, 0x62, 0x5f, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e,
	0x41, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x53, 0x63, 0x68, 0x65, 0x64, 0x75, 0x6c,
	0x65, 0x72, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0a, 0x73, 0x63, 0x68, 0x65, 0x64, 0x75,
	0x6c, 0x65, 0x72, 0x73, 0x12, 0x3b, 0x0a, 0x1a, 0x6d, 0x61, 0x78, 0x69, 0x6d, 0x75, 0x6d, 0x5f,
	0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x5f, 0x73, 0x69, 0x7a, 0x65, 0x5f, 0x62, 0x79, 0x74,
	0x65, 0x73, 0x18, 0x08, 0x20, 0x01, 0x28, 0x03, 0x52, 0x17, 0x6d, 0x61, 0x78, 0x69, 0x6d, 0x75,
	0x6d, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x53, 0x69, 0x7a, 0x65, 0x42, 0x79, 0x74, 0x65,
	0x73, 0x12, 0x45, 0x0a, 0x06, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x18, 0x09, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x2d, 0x2e, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x62, 0x61, 0x72, 0x6e, 0x2e, 0x63, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x67, 0x6c, 0x6f, 0x62,
	0x61, 0x6c, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x52, 0x06, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x12, 0x8b, 0x01, 0x0a, 0x24, 0x69, 0x6e, 0x64,
	0x69, 0x72, 0x65, 0x63, 0x74, 0x5f, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x5f, 0x61, 0x64,
	0x64, 0x72, 0x65, 0x73, 0x73, 0x61, 0x62, 0x6c, 0x65, 0x5f, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67,
	0x65, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x3a, 0x2e, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x62,
	0x61, 0x72, 0x6e, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x2e, 0x62, 0x6c, 0x6f, 0x62, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x42, 0x6c, 0x6f, 0x62,
	0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x52, 0x21, 0x69, 0x6e, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x43, 0x6f, 0x6e,
	0x74, 0x65, 0x6e, 0x74, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x61, 0x62, 0x6c, 0x65, 0x53,
	0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x12, 0x73, 0x0a, 0x18, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x61,
	0x6c, 0x5f, 0x73, 0x69, 0x7a, 0x65, 0x5f, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x5f, 0x63, 0x61, 0x63,
	0x68, 0x65, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x3a, 0x2e, 0x62, 0x75, 0x69, 0x6c, 0x64,
	0x62, 0x61, 0x72, 0x6e, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x2e, 0x62, 0x6c, 0x6f, 0x62, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x42, 0x6c, 0x6f,
	0x62, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x52, 0x15, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x6c, 0x53, 0x69, 0x7a,
	0x65, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x43, 0x61, 0x63, 0x68, 0x65, 0x12, 0x9c, 0x01, 0x0a, 0x27,
	0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x61,
	0x62, 0x6c, 0x65, 0x5f, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x5f, 0x61, 0x75, 0x74, 0x68,
	0x6f, 0x72, 0x69, 0x7a, 0x65, 0x72, 0x73, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x45, 0x2e,
	0x62, 0x75, 0x69, 0x6c, 0x64, 0x62, 0x61, 0x72, 0x6e, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x62, 0x62, 0x5f, 0x73, 0x74, 0x6f, 0x72, 0x61,
	0x67, 0x65, 0x2e, 0x53, 0x63, 0x61, 0x6e, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x41, 0x75, 0x74, 0x68,
	0x6f, 0x72, 0x69, 0x7a, 0x65, 0x72, 0x73, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x52, 0x24, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x41, 0x64, 0x64,
	0x72, 0x65, 0x73, 0x73, 0x61, 0x62, 0x6c, 0x65, 0x53, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x41,
	0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x72, 0x73, 0x12, 0xad, 0x01, 0x0a, 0x30, 0x69,
	0x6e, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x5f, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x5f,
	0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x61, 0x62, 0x6c, 0x65, 0x5f, 0x73, 0x74, 0x6f, 0x72,
	0x61, 0x67, 0x65, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x72, 0x73, 0x18,
	0x0d, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x45, 0x2e, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x62, 0x61, 0x72,
	0x6e, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e,
	0x62, 0x62, 0x5f, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x53, 0x63, 0x61, 0x6e, 0x6e,
	0x61, 0x62, 0x6c, 0x65, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x72, 0x73, 0x43,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x2c, 0x69, 0x6e,
	0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x41, 0x64, 0x64,
	0x72, 0x65, 0x73, 0x73, 0x61, 0x62, 0x6c, 0x65, 0x53, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x41,
	0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x72, 0x73, 0x12, 0x82, 0x01, 0x0a, 0x18, 0x61,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x63, 0x61, 0x63, 0x68, 0x65, 0x5f, 0x61, 0x75, 0x74, 0x68,
	0x6f, 0x72, 0x69, 0x7a, 0x65, 0x72, 0x73, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x48, 0x2e,
	0x62, 0x75, 0x69, 0x6c, 0x64, 0x62, 0x61, 0x72, 0x6e, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x62, 0x62, 0x5f, 0x73, 0x74, 0x6f, 0x72, 0x61,
	0x67, 0x65, 0x2e, 0x4e, 0x6f, 0x6e, 0x53, 0x63, 0x61, 0x6e, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x41,
	0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x72, 0x73, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x16, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x43,
	0x61, 0x63, 0x68, 0x65, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x72, 0x73, 0x12,
	0x98, 0x01, 0x0a, 0x24, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x6c, 0x5f, 0x73, 0x69, 0x7a, 0x65,
	0x5f, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x5f, 0x63, 0x61, 0x63, 0x68, 0x65, 0x5f, 0x61, 0x75, 0x74,
	0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x72, 0x73, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x48,
	0x2e, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x62, 0x61, 0x72, 0x6e, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x62, 0x62, 0x5f, 0x73, 0x74, 0x6f, 0x72,
	0x61, 0x67, 0x65, 0x2e, 0x4e, 0x6f, 0x6e, 0x53, 0x63, 0x61, 0x6e, 0x6e, 0x61, 0x62, 0x6c, 0x65,
	0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x72, 0x73, 0x43, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x20, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x61,
	0x6c, 0x53, 0x69, 0x7a, 0x65, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x43, 0x61, 0x63, 0x68, 0x65, 0x41,
	0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x72, 0x73, 0x12, 0x64, 0x0a, 0x12, 0x65, 0x78,
	0x65, 0x63, 0x75, 0x74, 0x65, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x72,
	0x18, 0x10, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x35, 0x2e, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x62, 0x61,
	0x72, 0x6e, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x2e, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x72,
	0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x11, 0x65,
	0x78, 0x65, 0x63, 0x75, 0x74, 0x65, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x72,
	0x1a, 0x76, 0x0a, 0x0f, 0x53, 0x63, 0x68, 0x65, 0x64, 0x75, 0x6c, 0x65, 0x72, 0x73, 0x45, 0x6e,
	0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x4d, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x37, 0x2e, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x62, 0x61, 0x72, 0x6e,
	0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x62,
	0x75, 0x69, 0x6c, 0x64, 0x65, 0x72, 0x2e, 0x53, 0x63, 0x68, 0x65, 0x64, 0x75, 0x6c, 0x65, 0x72,
	0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x05, 0x76,
	0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x4a, 0x04, 0x08, 0x02, 0x10, 0x03, 0x4a, 0x04,
	0x08, 0x03, 0x10, 0x04, 0x4a, 0x04, 0x08, 0x06, 0x10, 0x07, 0x4a, 0x04, 0x08, 0x07, 0x10, 0x08,
	0x22, 0xb8, 0x01, 0x0a, 0x24, 0x4e, 0x6f, 0x6e, 0x53, 0x63, 0x61, 0x6e, 0x6e, 0x61, 0x62, 0x6c,
	0x65, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x72, 0x73, 0x43, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x47, 0x0a, 0x03, 0x67, 0x65, 0x74,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x35, 0x2e, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x62, 0x61,
	0x72, 0x6e, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x2e, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x72,
	0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x03, 0x67,
	0x65, 0x74, 0x12, 0x47, 0x0a, 0x03, 0x70, 0x75, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x35, 0x2e, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x62, 0x61, 0x72, 0x6e, 0x2e, 0x63, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x41,
	0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x72, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75,
	0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x03, 0x70, 0x75, 0x74, 0x22, 0x8f, 0x02, 0x0a, 0x21,
	0x53, 0x63, 0x61, 0x6e, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69,
	0x7a, 0x65, 0x72, 0x73, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x12, 0x47, 0x0a, 0x03, 0x67, 0x65, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x35,
	0x2e, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x62, 0x61, 0x72, 0x6e, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x41, 0x75,
	0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x72, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x03, 0x67, 0x65, 0x74, 0x12, 0x47, 0x0a, 0x03, 0x70, 0x75,
	0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x35, 0x2e, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x62,
	0x61, 0x72, 0x6e, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65,
	0x72, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x03,
	0x70, 0x75, 0x74, 0x12, 0x58, 0x0a, 0x0c, 0x66, 0x69, 0x6e, 0x64, 0x5f, 0x6d, 0x69, 0x73, 0x73,
	0x69, 0x6e, 0x67, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x35, 0x2e, 0x62, 0x75, 0x69, 0x6c,
	0x64, 0x62, 0x61, 0x72, 0x6e, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69,
	0x7a, 0x65, 0x72, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x52, 0x0b, 0x66, 0x69, 0x6e, 0x64, 0x4d, 0x69, 0x73, 0x73, 0x69, 0x6e, 0x67, 0x42, 0x44, 0x5a,
	0x42, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x62, 0x75, 0x69, 0x6c,
	0x64, 0x62, 0x61, 0x72, 0x6e, 0x2f, 0x62, 0x62, 0x2d, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65,
	0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x62, 0x62, 0x5f, 0x73, 0x74, 0x6f, 0x72,
	0x61, 0x67, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_pkg_proto_configuration_bb_storage_bb_storage_proto_rawDescOnce sync.Once
	file_pkg_proto_configuration_bb_storage_bb_storage_proto_rawDescData = file_pkg_proto_configuration_bb_storage_bb_storage_proto_rawDesc
)

func file_pkg_proto_configuration_bb_storage_bb_storage_proto_rawDescGZIP() []byte {
	file_pkg_proto_configuration_bb_storage_bb_storage_proto_rawDescOnce.Do(func() {
		file_pkg_proto_configuration_bb_storage_bb_storage_proto_rawDescData = protoimpl.X.CompressGZIP(file_pkg_proto_configuration_bb_storage_bb_storage_proto_rawDescData)
	})
	return file_pkg_proto_configuration_bb_storage_bb_storage_proto_rawDescData
}

var (
	file_pkg_proto_configuration_bb_storage_bb_storage_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
	file_pkg_proto_configuration_bb_storage_bb_storage_proto_goTypes  = []interface{}{
		(*ApplicationConfiguration)(nil),             // 0: buildbarn.configuration.bb_storage.ApplicationConfiguration
		(*NonScannableAuthorizersConfiguration)(nil), // 1: buildbarn.configuration.bb_storage.NonScannableAuthorizersConfiguration
		(*ScannableAuthorizersConfiguration)(nil),    // 2: buildbarn.configuration.bb_storage.ScannableAuthorizersConfiguration
		nil,                                       // 3: buildbarn.configuration.bb_storage.ApplicationConfiguration.SchedulersEntry
		(*blobstore.BlobstoreConfiguration)(nil),  // 4: buildbarn.configuration.blobstore.BlobstoreConfiguration
		(*grpc.ServerConfiguration)(nil),          // 5: buildbarn.configuration.grpc.ServerConfiguration
		(*global.Configuration)(nil),              // 6: buildbarn.configuration.global.Configuration
		(*blobstore.BlobAccessConfiguration)(nil), // 7: buildbarn.configuration.blobstore.BlobAccessConfiguration
		(*auth.AuthorizerConfiguration)(nil),      // 8: buildbarn.configuration.auth.AuthorizerConfiguration
		(*builder.SchedulerConfiguration)(nil),    // 9: buildbarn.configuration.builder.SchedulerConfiguration
	}
)

var file_pkg_proto_configuration_bb_storage_bb_storage_proto_depIdxs = []int32{
	4,  // 0: buildbarn.configuration.bb_storage.ApplicationConfiguration.blobstore:type_name -> buildbarn.configuration.blobstore.BlobstoreConfiguration
	5,  // 1: buildbarn.configuration.bb_storage.ApplicationConfiguration.grpc_servers:type_name -> buildbarn.configuration.grpc.ServerConfiguration
	3,  // 2: buildbarn.configuration.bb_storage.ApplicationConfiguration.schedulers:type_name -> buildbarn.configuration.bb_storage.ApplicationConfiguration.SchedulersEntry
	6,  // 3: buildbarn.configuration.bb_storage.ApplicationConfiguration.global:type_name -> buildbarn.configuration.global.Configuration
	7,  // 4: buildbarn.configuration.bb_storage.ApplicationConfiguration.indirect_content_addressable_storage:type_name -> buildbarn.configuration.blobstore.BlobAccessConfiguration
	7,  // 5: buildbarn.configuration.bb_storage.ApplicationConfiguration.initial_size_class_cache:type_name -> buildbarn.configuration.blobstore.BlobAccessConfiguration
	2,  // 6: buildbarn.configuration.bb_storage.ApplicationConfiguration.content_addressable_storage_authorizers:type_name -> buildbarn.configuration.bb_storage.ScannableAuthorizersConfiguration
	2,  // 7: buildbarn.configuration.bb_storage.ApplicationConfiguration.indirect_content_addressable_storage_authorizers:type_name -> buildbarn.configuration.bb_storage.ScannableAuthorizersConfiguration
	1,  // 8: buildbarn.configuration.bb_storage.ApplicationConfiguration.action_cache_authorizers:type_name -> buildbarn.configuration.bb_storage.NonScannableAuthorizersConfiguration
	1,  // 9: buildbarn.configuration.bb_storage.ApplicationConfiguration.initial_size_class_cache_authorizers:type_name -> buildbarn.configuration.bb_storage.NonScannableAuthorizersConfiguration
	8,  // 10: buildbarn.configuration.bb_storage.ApplicationConfiguration.execute_authorizer:type_name -> buildbarn.configuration.auth.AuthorizerConfiguration
	8,  // 11: buildbarn.configuration.bb_storage.NonScannableAuthorizersConfiguration.get:type_name -> buildbarn.configuration.auth.AuthorizerConfiguration
	8,  // 12: buildbarn.configuration.bb_storage.NonScannableAuthorizersConfiguration.put:type_name -> buildbarn.configuration.auth.AuthorizerConfiguration
	8,  // 13: buildbarn.configuration.bb_storage.ScannableAuthorizersConfiguration.get:type_name -> buildbarn.configuration.auth.AuthorizerConfiguration
	8,  // 14: buildbarn.configuration.bb_storage.ScannableAuthorizersConfiguration.put:type_name -> buildbarn.configuration.auth.AuthorizerConfiguration
	8,  // 15: buildbarn.configuration.bb_storage.ScannableAuthorizersConfiguration.find_missing:type_name -> buildbarn.configuration.auth.AuthorizerConfiguration
	9,  // 16: buildbarn.configuration.bb_storage.ApplicationConfiguration.SchedulersEntry.value:type_name -> buildbarn.configuration.builder.SchedulerConfiguration
	17, // [17:17] is the sub-list for method output_type
	17, // [17:17] is the sub-list for method input_type
	17, // [17:17] is the sub-list for extension type_name
	17, // [17:17] is the sub-list for extension extendee
	0,  // [0:17] is the sub-list for field type_name
}

func init() { file_pkg_proto_configuration_bb_storage_bb_storage_proto_init() }
func file_pkg_proto_configuration_bb_storage_bb_storage_proto_init() {
	if File_pkg_proto_configuration_bb_storage_bb_storage_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_pkg_proto_configuration_bb_storage_bb_storage_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ApplicationConfiguration); i {
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
		file_pkg_proto_configuration_bb_storage_bb_storage_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*NonScannableAuthorizersConfiguration); i {
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
		file_pkg_proto_configuration_bb_storage_bb_storage_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ScannableAuthorizersConfiguration); i {
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
			RawDescriptor: file_pkg_proto_configuration_bb_storage_bb_storage_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_pkg_proto_configuration_bb_storage_bb_storage_proto_goTypes,
		DependencyIndexes: file_pkg_proto_configuration_bb_storage_bb_storage_proto_depIdxs,
		MessageInfos:      file_pkg_proto_configuration_bb_storage_bb_storage_proto_msgTypes,
	}.Build()
	File_pkg_proto_configuration_bb_storage_bb_storage_proto = out.File
	file_pkg_proto_configuration_bb_storage_bb_storage_proto_rawDesc = nil
	file_pkg_proto_configuration_bb_storage_bb_storage_proto_goTypes = nil
	file_pkg_proto_configuration_bb_storage_bb_storage_proto_depIdxs = nil
}
