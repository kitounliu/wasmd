// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: cosmos-cash/verifiable-credential/crypto/accumulator/accumulator.proto

package accumulator

import (
	fmt "fmt"
	proto "github.com/gogo/protobuf/proto"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type PrivateKey struct {
	Value []byte `protobuf:"bytes,1,opt,name=value,proto3" json:"value,omitempty"`
}

func (m *PrivateKey) Reset()         { *m = PrivateKey{} }
func (m *PrivateKey) String() string { return proto.CompactTextString(m) }
func (*PrivateKey) ProtoMessage()    {}
func (*PrivateKey) Descriptor() ([]byte, []int) {
	return fileDescriptor_650de2d02882b57c, []int{0}
}
func (m *PrivateKey) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *PrivateKey) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_PrivateKey.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *PrivateKey) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PrivateKey.Merge(m, src)
}
func (m *PrivateKey) XXX_Size() int {
	return m.Size()
}
func (m *PrivateKey) XXX_DiscardUnknown() {
	xxx_messageInfo_PrivateKey.DiscardUnknown(m)
}

var xxx_messageInfo_PrivateKey proto.InternalMessageInfo

func (m *PrivateKey) GetValue() []byte {
	if m != nil {
		return m.Value
	}
	return nil
}

type PublicParameters struct {
	PublicKey []byte `protobuf:"bytes,1,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	State     *State `protobuf:"bytes,2,opt,name=state,proto3" json:"state,omitempty"`
}

func (m *PublicParameters) Reset()         { *m = PublicParameters{} }
func (m *PublicParameters) String() string { return proto.CompactTextString(m) }
func (*PublicParameters) ProtoMessage()    {}
func (*PublicParameters) Descriptor() ([]byte, []int) {
	return fileDescriptor_650de2d02882b57c, []int{1}
}
func (m *PublicParameters) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *PublicParameters) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_PublicParameters.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *PublicParameters) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PublicParameters.Merge(m, src)
}
func (m *PublicParameters) XXX_Size() int {
	return m.Size()
}
func (m *PublicParameters) XXX_DiscardUnknown() {
	xxx_messageInfo_PublicParameters.DiscardUnknown(m)
}

var xxx_messageInfo_PublicParameters proto.InternalMessageInfo

func (m *PublicParameters) GetPublicKey() []byte {
	if m != nil {
		return m.PublicKey
	}
	return nil
}

func (m *PublicParameters) GetState() *State {
	if m != nil {
		return m.State
	}
	return nil
}

type State struct {
	AccValue []byte       `protobuf:"bytes,1,opt,name=acc_value,json=accValue,proto3" json:"acc_value,omitempty"`
	Update   *BatchUpdate `protobuf:"bytes,2,opt,name=update,proto3" json:"update,omitempty"`
}

func (m *State) Reset()         { *m = State{} }
func (m *State) String() string { return proto.CompactTextString(m) }
func (*State) ProtoMessage()    {}
func (*State) Descriptor() ([]byte, []int) {
	return fileDescriptor_650de2d02882b57c, []int{2}
}
func (m *State) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *State) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_State.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *State) XXX_Merge(src proto.Message) {
	xxx_messageInfo_State.Merge(m, src)
}
func (m *State) XXX_Size() int {
	return m.Size()
}
func (m *State) XXX_DiscardUnknown() {
	xxx_messageInfo_State.DiscardUnknown(m)
}

var xxx_messageInfo_State proto.InternalMessageInfo

func (m *State) GetAccValue() []byte {
	if m != nil {
		return m.AccValue
	}
	return nil
}

func (m *State) GetUpdate() *BatchUpdate {
	if m != nil {
		return m.Update
	}
	return nil
}

type BatchUpdate struct {
	Additions    []byte `protobuf:"bytes,1,opt,name=additions,proto3" json:"additions,omitempty"`
	Deletions    []byte `protobuf:"bytes,2,opt,name=deletions,proto3" json:"deletions,omitempty"`
	Coefficients []byte `protobuf:"bytes,3,opt,name=coefficients,proto3" json:"coefficients,omitempty"`
}

func (m *BatchUpdate) Reset()         { *m = BatchUpdate{} }
func (m *BatchUpdate) String() string { return proto.CompactTextString(m) }
func (*BatchUpdate) ProtoMessage()    {}
func (*BatchUpdate) Descriptor() ([]byte, []int) {
	return fileDescriptor_650de2d02882b57c, []int{3}
}
func (m *BatchUpdate) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *BatchUpdate) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_BatchUpdate.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *BatchUpdate) XXX_Merge(src proto.Message) {
	xxx_messageInfo_BatchUpdate.Merge(m, src)
}
func (m *BatchUpdate) XXX_Size() int {
	return m.Size()
}
func (m *BatchUpdate) XXX_DiscardUnknown() {
	xxx_messageInfo_BatchUpdate.DiscardUnknown(m)
}

var xxx_messageInfo_BatchUpdate proto.InternalMessageInfo

func (m *BatchUpdate) GetAdditions() []byte {
	if m != nil {
		return m.Additions
	}
	return nil
}

func (m *BatchUpdate) GetDeletions() []byte {
	if m != nil {
		return m.Deletions
	}
	return nil
}

func (m *BatchUpdate) GetCoefficients() []byte {
	if m != nil {
		return m.Coefficients
	}
	return nil
}

type Proof struct {
	Entropy      []byte `protobuf:"bytes,1,opt,name=entropy,proto3" json:"entropy,omitempty"`
	ChallengeOkm []byte `protobuf:"bytes,2,opt,name=challenge_okm,json=challengeOkm,proto3" json:"challenge_okm,omitempty"`
	Proof        []byte `protobuf:"bytes,3,opt,name=proof,proto3" json:"proof,omitempty"`
}

func (m *Proof) Reset()         { *m = Proof{} }
func (m *Proof) String() string { return proto.CompactTextString(m) }
func (*Proof) ProtoMessage()    {}
func (*Proof) Descriptor() ([]byte, []int) {
	return fileDescriptor_650de2d02882b57c, []int{4}
}
func (m *Proof) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Proof) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Proof.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Proof) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Proof.Merge(m, src)
}
func (m *Proof) XXX_Size() int {
	return m.Size()
}
func (m *Proof) XXX_DiscardUnknown() {
	xxx_messageInfo_Proof.DiscardUnknown(m)
}

var xxx_messageInfo_Proof proto.InternalMessageInfo

func (m *Proof) GetEntropy() []byte {
	if m != nil {
		return m.Entropy
	}
	return nil
}

func (m *Proof) GetChallengeOkm() []byte {
	if m != nil {
		return m.ChallengeOkm
	}
	return nil
}

func (m *Proof) GetProof() []byte {
	if m != nil {
		return m.Proof
	}
	return nil
}

func init() {
	proto.RegisterType((*PrivateKey)(nil), "wasmd.verifiablecredential.crypto.accumulator.PrivateKey")
	proto.RegisterType((*PublicParameters)(nil), "wasmd.verifiablecredential.crypto.accumulator.PublicParameters")
	proto.RegisterType((*State)(nil), "wasmd.verifiablecredential.crypto.accumulator.State")
	proto.RegisterType((*BatchUpdate)(nil), "wasmd.verifiablecredential.crypto.accumulator.BatchUpdate")
	proto.RegisterType((*Proof)(nil), "wasmd.verifiablecredential.crypto.accumulator.Proof")
}

func init() {
	proto.RegisterFile("cosmos-cash/verifiable-credential/crypto/accumulator/accumulator.proto", fileDescriptor_650de2d02882b57c)
}

var fileDescriptor_650de2d02882b57c = []byte{
	// 401 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x92, 0xbf, 0x8e, 0xd3, 0x40,
	0x10, 0xc6, 0xe3, 0x43, 0x39, 0xc8, 0x5c, 0x90, 0xd0, 0x8a, 0x22, 0x12, 0x60, 0x9d, 0x4c, 0x73,
	0x4d, 0x6c, 0x09, 0xa8, 0x28, 0x0f, 0x44, 0x01, 0x05, 0x51, 0x10, 0x20, 0x21, 0x44, 0x34, 0x19,
	0x8f, 0xcf, 0xab, 0xec, 0x7a, 0xad, 0xdd, 0x75, 0xb8, 0x14, 0xbc, 0x03, 0x8f, 0x45, 0x79, 0x25,
	0x25, 0x4a, 0x5e, 0x04, 0xf9, 0x4f, 0x12, 0xd3, 0x71, 0x9d, 0xbf, 0x6f, 0x76, 0x7f, 0xdf, 0x78,
	0x76, 0xe0, 0x0d, 0x19, 0xa7, 0x8d, 0x9b, 0x12, 0xba, 0x3c, 0x59, 0xb3, 0x95, 0x99, 0xc4, 0xa5,
	0xe2, 0x29, 0x59, 0x4e, 0xb9, 0xf0, 0x12, 0x55, 0x42, 0x76, 0x53, 0x7a, 0x93, 0x20, 0x51, 0xa5,
	0x2b, 0x85, 0xde, 0xd8, 0xfe, 0x77, 0x5c, 0x5a, 0xe3, 0x8d, 0x98, 0x7e, 0x47, 0xa7, 0xd3, 0xf8,
	0x48, 0x38, 0x02, 0xe2, 0x16, 0x10, 0xf7, 0x2e, 0x45, 0x11, 0xc0, 0xcc, 0xca, 0x35, 0x7a, 0x7e,
	0xc7, 0x1b, 0xf1, 0x10, 0x86, 0x6b, 0x54, 0x15, 0x4f, 0x82, 0xf3, 0xe0, 0x62, 0x3c, 0x6f, 0x45,
	0xf4, 0x03, 0x1e, 0xcc, 0xaa, 0xa5, 0x92, 0x34, 0x43, 0x8b, 0x9a, 0x3d, 0x5b, 0x27, 0x9e, 0x00,
	0x94, 0x8d, 0xb7, 0x58, 0xf1, 0xa6, 0x3b, 0x3e, 0x6a, 0x9d, 0x1a, 0xf4, 0x16, 0x86, 0xce, 0xa3,
	0xe7, 0xc9, 0xc9, 0x79, 0x70, 0x71, 0xf6, 0xec, 0x45, 0x7c, 0xab, 0xae, 0xe2, 0x0f, 0xf5, 0xdd,
	0x79, 0x8b, 0x88, 0xae, 0x61, 0xd8, 0x68, 0xf1, 0x08, 0x46, 0x48, 0xb4, 0xe8, 0x77, 0x78, 0x0f,
	0x89, 0x3e, 0xd5, 0x5a, 0xcc, 0xe1, 0xb4, 0x2a, 0xd3, 0x63, 0xe4, 0xcb, 0x5b, 0x46, 0x5e, 0xa2,
	0xa7, 0xfc, 0x63, 0x43, 0x98, 0x77, 0xa4, 0x48, 0xc3, 0x59, 0xcf, 0x16, 0x8f, 0x61, 0x84, 0x69,
	0x2a, 0xbd, 0x34, 0x85, 0xdb, 0xff, 0xf2, 0xc1, 0xa8, 0xab, 0x29, 0x2b, 0x6e, 0xab, 0x27, 0x6d,
	0xf5, 0x60, 0x88, 0x08, 0xc6, 0x64, 0x38, 0xcb, 0x24, 0x49, 0x2e, 0xbc, 0x9b, 0xdc, 0x69, 0x0e,
	0xfc, 0xe3, 0x45, 0x5f, 0x61, 0x38, 0xb3, 0xc6, 0x64, 0x62, 0x02, 0x77, 0xb9, 0xf0, 0xd6, 0x94,
	0xfb, 0xc9, 0xee, 0xa5, 0x78, 0x0a, 0xf7, 0x29, 0x47, 0xa5, 0xb8, 0xb8, 0xe2, 0x85, 0x59, 0xe9,
	0x2e, 0x68, 0x7c, 0x30, 0xdf, 0xaf, 0x74, 0xfd, 0x8a, 0x65, 0xcd, 0xe9, 0x42, 0x5a, 0x71, 0xf9,
	0xed, 0xd7, 0x36, 0x0c, 0x6e, 0xb6, 0x61, 0xf0, 0x67, 0x1b, 0x06, 0x3f, 0x77, 0xe1, 0xe0, 0x66,
	0x17, 0x0e, 0x7e, 0xef, 0xc2, 0xc1, 0x97, 0xd7, 0x57, 0xd2, 0xe7, 0xd5, 0x32, 0x26, 0xa3, 0x93,
	0x57, 0xc6, 0xe9, 0xcf, 0xe8, 0x74, 0xd2, 0x4c, 0x2f, 0xb9, 0xfe, 0xef, 0x55, 0x5c, 0x9e, 0x36,
	0xfb, 0xf7, 0xfc, 0x6f, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0xaf, 0x39, 0x5a, 0xc9, 0x02, 0x00,
	0x00,
}

func (m *PrivateKey) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *PrivateKey) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *PrivateKey) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Value) > 0 {
		i -= len(m.Value)
		copy(dAtA[i:], m.Value)
		i = encodeVarintAccumulator(dAtA, i, uint64(len(m.Value)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *PublicParameters) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *PublicParameters) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *PublicParameters) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.State != nil {
		{
			size, err := m.State.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintAccumulator(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x12
	}
	if len(m.PublicKey) > 0 {
		i -= len(m.PublicKey)
		copy(dAtA[i:], m.PublicKey)
		i = encodeVarintAccumulator(dAtA, i, uint64(len(m.PublicKey)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *State) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *State) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *State) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.Update != nil {
		{
			size, err := m.Update.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintAccumulator(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x12
	}
	if len(m.AccValue) > 0 {
		i -= len(m.AccValue)
		copy(dAtA[i:], m.AccValue)
		i = encodeVarintAccumulator(dAtA, i, uint64(len(m.AccValue)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *BatchUpdate) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *BatchUpdate) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *BatchUpdate) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Coefficients) > 0 {
		i -= len(m.Coefficients)
		copy(dAtA[i:], m.Coefficients)
		i = encodeVarintAccumulator(dAtA, i, uint64(len(m.Coefficients)))
		i--
		dAtA[i] = 0x1a
	}
	if len(m.Deletions) > 0 {
		i -= len(m.Deletions)
		copy(dAtA[i:], m.Deletions)
		i = encodeVarintAccumulator(dAtA, i, uint64(len(m.Deletions)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.Additions) > 0 {
		i -= len(m.Additions)
		copy(dAtA[i:], m.Additions)
		i = encodeVarintAccumulator(dAtA, i, uint64(len(m.Additions)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *Proof) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Proof) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Proof) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Proof) > 0 {
		i -= len(m.Proof)
		copy(dAtA[i:], m.Proof)
		i = encodeVarintAccumulator(dAtA, i, uint64(len(m.Proof)))
		i--
		dAtA[i] = 0x1a
	}
	if len(m.ChallengeOkm) > 0 {
		i -= len(m.ChallengeOkm)
		copy(dAtA[i:], m.ChallengeOkm)
		i = encodeVarintAccumulator(dAtA, i, uint64(len(m.ChallengeOkm)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.Entropy) > 0 {
		i -= len(m.Entropy)
		copy(dAtA[i:], m.Entropy)
		i = encodeVarintAccumulator(dAtA, i, uint64(len(m.Entropy)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintAccumulator(dAtA []byte, offset int, v uint64) int {
	offset -= sovAccumulator(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *PrivateKey) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Value)
	if l > 0 {
		n += 1 + l + sovAccumulator(uint64(l))
	}
	return n
}

func (m *PublicParameters) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.PublicKey)
	if l > 0 {
		n += 1 + l + sovAccumulator(uint64(l))
	}
	if m.State != nil {
		l = m.State.Size()
		n += 1 + l + sovAccumulator(uint64(l))
	}
	return n
}

func (m *State) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.AccValue)
	if l > 0 {
		n += 1 + l + sovAccumulator(uint64(l))
	}
	if m.Update != nil {
		l = m.Update.Size()
		n += 1 + l + sovAccumulator(uint64(l))
	}
	return n
}

func (m *BatchUpdate) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Additions)
	if l > 0 {
		n += 1 + l + sovAccumulator(uint64(l))
	}
	l = len(m.Deletions)
	if l > 0 {
		n += 1 + l + sovAccumulator(uint64(l))
	}
	l = len(m.Coefficients)
	if l > 0 {
		n += 1 + l + sovAccumulator(uint64(l))
	}
	return n
}

func (m *Proof) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Entropy)
	if l > 0 {
		n += 1 + l + sovAccumulator(uint64(l))
	}
	l = len(m.ChallengeOkm)
	if l > 0 {
		n += 1 + l + sovAccumulator(uint64(l))
	}
	l = len(m.Proof)
	if l > 0 {
		n += 1 + l + sovAccumulator(uint64(l))
	}
	return n
}

func sovAccumulator(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozAccumulator(x uint64) (n int) {
	return sovAccumulator(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *PrivateKey) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowAccumulator
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: PrivateKey: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: PrivateKey: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Value", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAccumulator
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthAccumulator
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthAccumulator
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Value = append(m.Value[:0], dAtA[iNdEx:postIndex]...)
			if m.Value == nil {
				m.Value = []byte{}
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipAccumulator(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthAccumulator
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *PublicParameters) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowAccumulator
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: PublicParameters: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: PublicParameters: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field PublicKey", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAccumulator
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthAccumulator
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthAccumulator
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.PublicKey = append(m.PublicKey[:0], dAtA[iNdEx:postIndex]...)
			if m.PublicKey == nil {
				m.PublicKey = []byte{}
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field State", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAccumulator
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthAccumulator
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthAccumulator
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.State == nil {
				m.State = &State{}
			}
			if err := m.State.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipAccumulator(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthAccumulator
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *State) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowAccumulator
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: State: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: State: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AccValue", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAccumulator
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthAccumulator
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthAccumulator
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.AccValue = append(m.AccValue[:0], dAtA[iNdEx:postIndex]...)
			if m.AccValue == nil {
				m.AccValue = []byte{}
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Update", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAccumulator
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthAccumulator
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthAccumulator
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Update == nil {
				m.Update = &BatchUpdate{}
			}
			if err := m.Update.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipAccumulator(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthAccumulator
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *BatchUpdate) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowAccumulator
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: BatchUpdate: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: BatchUpdate: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Additions", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAccumulator
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthAccumulator
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthAccumulator
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Additions = append(m.Additions[:0], dAtA[iNdEx:postIndex]...)
			if m.Additions == nil {
				m.Additions = []byte{}
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Deletions", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAccumulator
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthAccumulator
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthAccumulator
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Deletions = append(m.Deletions[:0], dAtA[iNdEx:postIndex]...)
			if m.Deletions == nil {
				m.Deletions = []byte{}
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Coefficients", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAccumulator
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthAccumulator
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthAccumulator
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Coefficients = append(m.Coefficients[:0], dAtA[iNdEx:postIndex]...)
			if m.Coefficients == nil {
				m.Coefficients = []byte{}
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipAccumulator(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthAccumulator
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *Proof) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowAccumulator
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Proof: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Proof: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Entropy", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAccumulator
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthAccumulator
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthAccumulator
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Entropy = append(m.Entropy[:0], dAtA[iNdEx:postIndex]...)
			if m.Entropy == nil {
				m.Entropy = []byte{}
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ChallengeOkm", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAccumulator
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthAccumulator
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthAccumulator
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ChallengeOkm = append(m.ChallengeOkm[:0], dAtA[iNdEx:postIndex]...)
			if m.ChallengeOkm == nil {
				m.ChallengeOkm = []byte{}
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Proof", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAccumulator
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthAccumulator
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthAccumulator
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Proof = append(m.Proof[:0], dAtA[iNdEx:postIndex]...)
			if m.Proof == nil {
				m.Proof = []byte{}
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipAccumulator(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthAccumulator
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipAccumulator(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowAccumulator
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowAccumulator
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowAccumulator
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthAccumulator
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupAccumulator
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthAccumulator
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthAccumulator        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowAccumulator          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupAccumulator = fmt.Errorf("proto: unexpected end of group")
)
