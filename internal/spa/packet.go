package spa

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// 包格式(大端序, 单个 UDP 数据报):
//
//	偏移  长度  字段
//	0     2     magic "SP"
//	2     1     version (=1)
//	3     1     userID 长度 (1..32)
//	4     N     userID
//	4+N   8     timestamp (Unix 秒)
//	12+N  16    nonce (随机)
//	28+N  2     port (请求放开的端口)
//	30+N  4     duration (请求放开秒数, 服务端钳制上限)
//	34+N  32    HMAC-SHA256(以上全部内容, key=用户密钥)
const (
	Version      = 1
	MaxUserIDLen = 32
	NonceLen     = 16
	hmacLen      = sha256.Size
	headerLen    = 2 + 1 + 1 // magic + version + userIDLen
	// MaxPacketLen 是合法包的最大字节数, 服务端直接按此截断读取。
	MaxPacketLen = headerLen + MaxUserIDLen + 8 + NonceLen + 2 + 4 + hmacLen
)

var magic = [2]byte{'S', 'P'}

// Packet 是一个待发送/已解析的授权请求。
type Packet struct {
	UserID    string
	Timestamp int64
	Nonce     [NonceLen]byte
	Port      uint16
	Duration  uint32 // 请求放开的秒数
}

// Marshal 用用户密钥对包编码并附加 HMAC。
func (p *Packet) Marshal(key []byte) ([]byte, error) {
	if len(p.UserID) == 0 || len(p.UserID) > MaxUserIDLen {
		return nil, fmt.Errorf("user id length must be 1..%d", MaxUserIDLen)
	}
	bodyLen := headerLen + len(p.UserID) + 8 + NonceLen + 2 + 4
	buf := make([]byte, bodyLen, bodyLen+hmacLen)
	buf[0], buf[1], buf[2] = magic[0], magic[1], Version
	buf[3] = byte(len(p.UserID))
	off := headerLen + copy(buf[headerLen:], p.UserID)
	binary.BigEndian.PutUint64(buf[off:], uint64(p.Timestamp))
	off += 8
	copy(buf[off:], p.Nonce[:])
	off += NonceLen
	binary.BigEndian.PutUint16(buf[off:], p.Port)
	off += 2
	binary.BigEndian.PutUint32(buf[off:], p.Duration)
	mac := hmac.New(sha256.New, key)
	mac.Write(buf)
	return mac.Sum(buf), nil
}

// Unmarshal 把数据报拆成包体、被签名的部分和 MAC。
// 注意: 它不校验 MAC —— 调用方需先按 UserID 查到密钥再 VerifyMAC。
func Unmarshal(data []byte) (pkt *Packet, signed []byte, mac []byte, err error) {
	if len(data) < headerLen+hmacLen || len(data) > MaxPacketLen {
		return nil, nil, nil, errors.New("bad packet length")
	}
	if data[0] != magic[0] || data[1] != magic[1] {
		return nil, nil, nil, errors.New("bad magic")
	}
	if data[2] != Version {
		return nil, nil, nil, fmt.Errorf("unsupported version %d", data[2])
	}
	uidLen := int(data[3])
	if uidLen == 0 || uidLen > MaxUserIDLen {
		return nil, nil, nil, errors.New("bad user id length")
	}
	bodyLen := headerLen + uidLen + 8 + NonceLen + 2 + 4
	if len(data) != bodyLen+hmacLen {
		return nil, nil, nil, errors.New("packet length mismatch")
	}
	signed = data[:bodyLen]
	mac = data[bodyLen:]
	p := &Packet{}
	off := headerLen
	p.UserID = string(data[off : off+uidLen])
	off += uidLen
	p.Timestamp = int64(binary.BigEndian.Uint64(data[off:]))
	off += 8
	copy(p.Nonce[:], data[off:off+NonceLen])
	off += NonceLen
	p.Port = binary.BigEndian.Uint16(data[off:])
	off += 2
	p.Duration = binary.BigEndian.Uint32(data[off:])
	return p, signed, mac, nil
}

// VerifyMAC 用指定密钥校验签名(常量时间比较)。
func VerifyMAC(key, signed, mac []byte) bool {
	m := hmac.New(sha256.New, key)
	m.Write(signed)
	return hmac.Equal(m.Sum(nil), mac)
}
