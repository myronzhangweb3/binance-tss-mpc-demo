// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: p2p/messages/signature_notifier.proto

package messages

import (
	fmt "fmt"
	proto "github.com/cosmos/gogoproto/proto"
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

type KeysignSignature_Status int32

const (
	KeysignSignature_Unknown KeysignSignature_Status = 0
	KeysignSignature_Success KeysignSignature_Status = 1
	KeysignSignature_Failed  KeysignSignature_Status = 2
)

var KeysignSignature_Status_name = map[int32]string{
	0: "Unknown",
	1: "Success",
	2: "Failed",
}

var KeysignSignature_Status_value = map[string]int32{
	"Unknown": 0,
	"Success": 1,
	"Failed":  2,
}

func (x KeysignSignature_Status) String() string {
	return proto.EnumName(KeysignSignature_Status_name, int32(x))
}

func (KeysignSignature_Status) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_5f4658f4647eb216, []int{0, 0}
}

type KeysignSignature struct {
	ID            string                  `protobuf:"bytes,1,opt,name=ID,proto3" json:"ID,omitempty"`
	Signatures    [][]byte                `protobuf:"bytes,2,rep,name=Signatures,proto3" json:"Signatures,omitempty"`
	KeysignStatus KeysignSignature_Status `protobuf:"varint,3,opt,name=KeysignStatus,proto3,enum=bifrost.p2p.messages.KeysignSignature_Status" json:"KeysignStatus,omitempty"`
}

func (m *KeysignSignature) Reset()         { *m = KeysignSignature{} }
func (m *KeysignSignature) String() string { return proto.CompactTextString(m) }
func (*KeysignSignature) ProtoMessage()    {}
func (*KeysignSignature) Descriptor() ([]byte, []int) {
	return fileDescriptor_5f4658f4647eb216, []int{0}
}
func (m *KeysignSignature) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *KeysignSignature) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_KeysignSignature.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *KeysignSignature) XXX_Merge(src proto.Message) {
	xxx_messageInfo_KeysignSignature.Merge(m, src)
}
func (m *KeysignSignature) XXX_Size() int {
	return m.Size()
}
func (m *KeysignSignature) XXX_DiscardUnknown() {
	xxx_messageInfo_KeysignSignature.DiscardUnknown(m)
}

var xxx_messageInfo_KeysignSignature proto.InternalMessageInfo

func (m *KeysignSignature) GetID() string {
	if m != nil {
		return m.ID
	}
	return ""
}

func (m *KeysignSignature) GetSignatures() [][]byte {
	if m != nil {
		return m.Signatures
	}
	return nil
}

func (m *KeysignSignature) GetKeysignStatus() KeysignSignature_Status {
	if m != nil {
		return m.KeysignStatus
	}
	return KeysignSignature_Unknown
}

func init() {
	proto.RegisterEnum("bifrost.p2p.messages.KeysignSignature_Status", KeysignSignature_Status_name, KeysignSignature_Status_value)
	proto.RegisterType((*KeysignSignature)(nil), "bifrost.p2p.messages.KeysignSignature")
}

func init() {
	proto.RegisterFile("p2p/messages/signature_notifier.proto", fileDescriptor_5f4658f4647eb216)
}

var fileDescriptor_5f4658f4647eb216 = []byte{
	// 268 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xd2, 0x4d, 0xca, 0x4c, 0x2b,
	0xca, 0x2f, 0x2e, 0xd1, 0x2f, 0x30, 0x2a, 0xd0, 0xcf, 0x4d, 0x2d, 0x2e, 0x4e, 0x4c, 0x4f, 0x2d,
	0xd6, 0x2f, 0xce, 0x4c, 0xcf, 0x4b, 0x2c, 0x29, 0x2d, 0x4a, 0x8d, 0xcf, 0xcb, 0x2f, 0xc9, 0x4c,
	0xcb, 0x4c, 0x2d, 0xd2, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x12, 0x81, 0x2a, 0xd7, 0x2b, 0x30,
	0x2a, 0xd0, 0x83, 0x29, 0x57, 0x3a, 0xce, 0xc8, 0x25, 0xe0, 0x9d, 0x5a, 0x09, 0xd2, 0x15, 0x0c,
	0xd3, 0x29, 0xc4, 0xc7, 0xc5, 0xe4, 0xe9, 0x22, 0xc1, 0xa8, 0xc0, 0xa8, 0xc1, 0x19, 0xc4, 0xe4,
	0xe9, 0x22, 0x24, 0xc7, 0xc5, 0x05, 0x97, 0x2c, 0x96, 0x60, 0x52, 0x60, 0xd6, 0xe0, 0x09, 0x42,
	0x12, 0x11, 0x0a, 0xe6, 0xe2, 0x85, 0x99, 0x51, 0x92, 0x58, 0x52, 0x5a, 0x2c, 0xc1, 0xac, 0xc0,
	0xa8, 0xc1, 0x67, 0xa4, 0xab, 0x87, 0xcd, 0x4a, 0x3d, 0x74, 0xeb, 0xf4, 0x20, 0x9a, 0x82, 0x50,
	0xcd, 0x50, 0xd2, 0xe3, 0x62, 0x83, 0xb0, 0x84, 0xb8, 0xb9, 0xd8, 0x43, 0xf3, 0xb2, 0xf3, 0xf2,
	0xcb, 0xf3, 0x04, 0x18, 0x40, 0x9c, 0xe0, 0xd2, 0xe4, 0xe4, 0xd4, 0xe2, 0x62, 0x01, 0x46, 0x21,
	0x2e, 0x2e, 0x36, 0xb7, 0xc4, 0xcc, 0x9c, 0xd4, 0x14, 0x01, 0x26, 0x27, 0xff, 0x13, 0x8f, 0xe4,
	0x18, 0x2f, 0x3c, 0x92, 0x63, 0x7c, 0xf0, 0x48, 0x8e, 0x71, 0xc2, 0x63, 0x39, 0x86, 0x0b, 0x8f,
	0xe5, 0x18, 0x6e, 0x3c, 0x96, 0x63, 0x88, 0x32, 0x4d, 0xcf, 0x2c, 0xc9, 0x49, 0x4c, 0xd2, 0x4b,
	0xce, 0xcf, 0xd5, 0x2f, 0xc9, 0xc8, 0x2f, 0x4a, 0xce, 0x48, 0xcc, 0xcc, 0x03, 0xb3, 0xf2, 0xf2,
	0x53, 0x52, 0xf5, 0xcb, 0x8c, 0xf5, 0xb1, 0x85, 0x64, 0x12, 0x1b, 0x38, 0xdc, 0x8c, 0x01, 0x01,
	0x00, 0x00, 0xff, 0xff, 0x73, 0x62, 0xb7, 0x23, 0x68, 0x01, 0x00, 0x00,
}

func (m *KeysignSignature) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *KeysignSignature) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *KeysignSignature) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.KeysignStatus != 0 {
		i = encodeVarintSignatureNotifier(dAtA, i, uint64(m.KeysignStatus))
		i--
		dAtA[i] = 0x18
	}
	if len(m.Signatures) > 0 {
		for iNdEx := len(m.Signatures) - 1; iNdEx >= 0; iNdEx-- {
			i -= len(m.Signatures[iNdEx])
			copy(dAtA[i:], m.Signatures[iNdEx])
			i = encodeVarintSignatureNotifier(dAtA, i, uint64(len(m.Signatures[iNdEx])))
			i--
			dAtA[i] = 0x12
		}
	}
	if len(m.ID) > 0 {
		i -= len(m.ID)
		copy(dAtA[i:], m.ID)
		i = encodeVarintSignatureNotifier(dAtA, i, uint64(len(m.ID)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintSignatureNotifier(dAtA []byte, offset int, v uint64) int {
	offset -= sovSignatureNotifier(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *KeysignSignature) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.ID)
	if l > 0 {
		n += 1 + l + sovSignatureNotifier(uint64(l))
	}
	if len(m.Signatures) > 0 {
		for _, b := range m.Signatures {
			l = len(b)
			n += 1 + l + sovSignatureNotifier(uint64(l))
		}
	}
	if m.KeysignStatus != 0 {
		n += 1 + sovSignatureNotifier(uint64(m.KeysignStatus))
	}
	return n
}

func sovSignatureNotifier(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozSignatureNotifier(x uint64) (n int) {
	return sovSignatureNotifier(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *KeysignSignature) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowSignatureNotifier
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
			return fmt.Errorf("proto: KeysignSignature: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: KeysignSignature: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ID", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowSignatureNotifier
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthSignatureNotifier
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthSignatureNotifier
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ID = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Signatures", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowSignatureNotifier
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
				return ErrInvalidLengthSignatureNotifier
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthSignatureNotifier
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Signatures = append(m.Signatures, make([]byte, postIndex-iNdEx))
			copy(m.Signatures[len(m.Signatures)-1], dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field KeysignStatus", wireType)
			}
			m.KeysignStatus = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowSignatureNotifier
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.KeysignStatus |= KeysignSignature_Status(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipSignatureNotifier(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthSignatureNotifier
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
func skipSignatureNotifier(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowSignatureNotifier
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
					return 0, ErrIntOverflowSignatureNotifier
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
					return 0, ErrIntOverflowSignatureNotifier
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
				return 0, ErrInvalidLengthSignatureNotifier
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupSignatureNotifier
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthSignatureNotifier
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthSignatureNotifier        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowSignatureNotifier          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupSignatureNotifier = fmt.Errorf("proto: unexpected end of group")
)
