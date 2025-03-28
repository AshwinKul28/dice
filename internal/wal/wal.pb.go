// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        v5.29.3
// source: internal/wal/wal.proto

package wal

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type EntryType int32

const (
	EntryType_ENTRY_TYPE_COMMAND     EntryType = 0
	EntryType_ENTRY_TYPE_CHECKPOINT  EntryType = 1
	EntryType_ENTRY_TYPE_TRANSACTION EntryType = 2
	EntryType_ENTRY_TYPE_REPLICATION EntryType = 3
)

// Enum value maps for EntryType.
var (
	EntryType_name = map[int32]string{
		0: "ENTRY_TYPE_COMMAND",
		1: "ENTRY_TYPE_CHECKPOINT",
		2: "ENTRY_TYPE_TRANSACTION",
		3: "ENTRY_TYPE_REPLICATION",
	}
	EntryType_value = map[string]int32{
		"ENTRY_TYPE_COMMAND":     0,
		"ENTRY_TYPE_CHECKPOINT":  1,
		"ENTRY_TYPE_TRANSACTION": 2,
		"ENTRY_TYPE_REPLICATION": 3,
	}
)

func (x EntryType) Enum() *EntryType {
	p := new(EntryType)
	*p = x
	return p
}

func (x EntryType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (EntryType) Descriptor() protoreflect.EnumDescriptor {
	return file_internal_wal_wal_proto_enumTypes[0].Descriptor()
}

func (EntryType) Type() protoreflect.EnumType {
	return &file_internal_wal_wal_proto_enumTypes[0]
}

func (x EntryType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use EntryType.Descriptor instead.
func (EntryType) EnumDescriptor() ([]byte, []int) {
	return file_internal_wal_wal_proto_rawDescGZIP(), []int{0}
}

type WALEntry struct {
	state             protoimpl.MessageState `protogen:"open.v1"`
	Version           string                 `protobuf:"bytes,1,opt,name=version,proto3" json:"version,omitempty"`                                                 // Version of the WAL entry (e.g., "v1.0")
	LogSequenceNumber uint64                 `protobuf:"varint,2,opt,name=log_sequence_number,json=logSequenceNumber,proto3" json:"log_sequence_number,omitempty"` // Log Sequence Number (LSN)
	Crc32             uint32                 `protobuf:"varint,4,opt,name=crc32,proto3" json:"crc32,omitempty"`                                                    // Cyclic Redundancy Check for integrity
	Timestamp         int64                  `protobuf:"varint,5,opt,name=timestamp,proto3" json:"timestamp,omitempty"`                                            // Timestamp for the WAL entry (epoch time in nanoseconds)
	// Cmd related fields
	EntryType     EntryType `protobuf:"varint,6,opt,name=entry_type,json=entryType,proto3,enum=wal.EntryType" json:"entry_type,omitempty"` // Type of the WAL entry
	Command       string    `protobuf:"bytes,7,opt,name=command,proto3" json:"command,omitempty"`                                          // The command being executed
	Args          []string  `protobuf:"bytes,8,rep,name=args,proto3" json:"args,omitempty"`                                                // Additional command arguments
	ClientId      string    `protobuf:"bytes,9,opt,name=client_id,json=clientId,proto3" json:"client_id,omitempty"`                        // ID of the client that issued the command
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *WALEntry) Reset() {
	*x = WALEntry{}
	mi := &file_internal_wal_wal_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *WALEntry) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*WALEntry) ProtoMessage() {}

func (x *WALEntry) ProtoReflect() protoreflect.Message {
	mi := &file_internal_wal_wal_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use WALEntry.ProtoReflect.Descriptor instead.
func (*WALEntry) Descriptor() ([]byte, []int) {
	return file_internal_wal_wal_proto_rawDescGZIP(), []int{0}
}

func (x *WALEntry) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *WALEntry) GetLogSequenceNumber() uint64 {
	if x != nil {
		return x.LogSequenceNumber
	}
	return 0
}

func (x *WALEntry) GetCrc32() uint32 {
	if x != nil {
		return x.Crc32
	}
	return 0
}

func (x *WALEntry) GetTimestamp() int64 {
	if x != nil {
		return x.Timestamp
	}
	return 0
}

func (x *WALEntry) GetEntryType() EntryType {
	if x != nil {
		return x.EntryType
	}
	return EntryType_ENTRY_TYPE_COMMAND
}

func (x *WALEntry) GetCommand() string {
	if x != nil {
		return x.Command
	}
	return ""
}

func (x *WALEntry) GetArgs() []string {
	if x != nil {
		return x.Args
	}
	return nil
}

func (x *WALEntry) GetClientId() string {
	if x != nil {
		return x.ClientId
	}
	return ""
}

var File_internal_wal_wal_proto protoreflect.FileDescriptor

const file_internal_wal_wal_proto_rawDesc = "" +
	"\n" +
	"\x16internal/wal/wal.proto\x12\x03wal\"\x82\x02\n" +
	"\bWALEntry\x12\x18\n" +
	"\aversion\x18\x01 \x01(\tR\aversion\x12.\n" +
	"\x13log_sequence_number\x18\x02 \x01(\x04R\x11logSequenceNumber\x12\x14\n" +
	"\x05crc32\x18\x04 \x01(\rR\x05crc32\x12\x1c\n" +
	"\ttimestamp\x18\x05 \x01(\x03R\ttimestamp\x12-\n" +
	"\n" +
	"entry_type\x18\x06 \x01(\x0e2\x0e.wal.EntryTypeR\tentryType\x12\x18\n" +
	"\acommand\x18\a \x01(\tR\acommand\x12\x12\n" +
	"\x04args\x18\b \x03(\tR\x04args\x12\x1b\n" +
	"\tclient_id\x18\t \x01(\tR\bclientId*v\n" +
	"\tEntryType\x12\x16\n" +
	"\x12ENTRY_TYPE_COMMAND\x10\x00\x12\x19\n" +
	"\x15ENTRY_TYPE_CHECKPOINT\x10\x01\x12\x1a\n" +
	"\x16ENTRY_TYPE_TRANSACTION\x10\x02\x12\x1a\n" +
	"\x16ENTRY_TYPE_REPLICATION\x10\x03B\x0eZ\finternal/walb\x06proto3"

var (
	file_internal_wal_wal_proto_rawDescOnce sync.Once
	file_internal_wal_wal_proto_rawDescData []byte
)

func file_internal_wal_wal_proto_rawDescGZIP() []byte {
	file_internal_wal_wal_proto_rawDescOnce.Do(func() {
		file_internal_wal_wal_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_internal_wal_wal_proto_rawDesc), len(file_internal_wal_wal_proto_rawDesc)))
	})
	return file_internal_wal_wal_proto_rawDescData
}

var file_internal_wal_wal_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_internal_wal_wal_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_internal_wal_wal_proto_goTypes = []any{
	(EntryType)(0),   // 0: wal.EntryType
	(*WALEntry)(nil), // 1: wal.WALEntry
}
var file_internal_wal_wal_proto_depIdxs = []int32{
	0, // 0: wal.WALEntry.entry_type:type_name -> wal.EntryType
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_internal_wal_wal_proto_init() }
func file_internal_wal_wal_proto_init() {
	if File_internal_wal_wal_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_internal_wal_wal_proto_rawDesc), len(file_internal_wal_wal_proto_rawDesc)),
			NumEnums:      1,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_internal_wal_wal_proto_goTypes,
		DependencyIndexes: file_internal_wal_wal_proto_depIdxs,
		EnumInfos:         file_internal_wal_wal_proto_enumTypes,
		MessageInfos:      file_internal_wal_wal_proto_msgTypes,
	}.Build()
	File_internal_wal_wal_proto = out.File
	file_internal_wal_wal_proto_goTypes = nil
	file_internal_wal_wal_proto_depIdxs = nil
}
