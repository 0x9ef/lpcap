// Copyright (c) 2022 0x9ef. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
package lpcap

import (
	"encoding/binary"
	"errors"
)

const lpcapmx = 0x4f3e
const minFileSize = 14
const minPacketSize = 10

type fileHeader struct {
	mx       uint16 // magic number
	majorVer uint16
	minorVer uint16
	snapLen  uint32
	link     LinkType
}

func unmarshalFileHeader(b []byte) (*fileHeader, int64, error) {
	erroffset := int64(0)
	h := &fileHeader{}
	mx := binary.LittleEndian.Uint16(b)
	if mx != lpcapmx {
		return nil, erroffset, errors.New("cannot parse PCAP file, invalid magix number")
	}
	h.mx = mx
	h.majorVer = binary.LittleEndian.Uint16(b[2:])
	if h.majorVer == 0 {
		erroffset += 2
		return nil, erroffset, errors.New("cannot parse PCAP file, invalid major version (is nil)")
	}
	h.minorVer = binary.LittleEndian.Uint16(b[4:])
	if h.minorVer == 0 {
		erroffset += 4
		return nil, erroffset, errors.New("cannot parse PCAP file, invalid minor version (is nil)")
	}
	h.snapLen = binary.LittleEndian.Uint32(b[6:])
	linkType := LinkType(binary.LittleEndian.Uint32(b[10:]))
	if linkType != LinkTypeEthernet2 && linkType != LinkTypeEthernet80211 {
		erroffset += 10
		return nil, erroffset, errors.New("cannot parse PCAP file, link type is undefined")
	}
	return h, 0, nil
}

type packetHeader struct {
	ifindex   uint8
	ptype     uint8
	timestamp uint32
	len       uint32
	p         []byte
}

func unmarshalPacketHeader(b []byte, maxLen uint32) (*packetHeader, int64, error) {
	erroffset := int64(0)
	h := &packetHeader{}
	i, pt := b[0], b[1]
	if pt != PtypeBroadcast && pt != PtypeUnicast && pt != PtypeMulticast {
		return nil, erroffset, errors.New("undefined packet type")
	}
	t := binary.LittleEndian.Uint32(b[2:])
	if t == 0 {
		erroffset += 2
		return nil, erroffset, errors.New("invalid timestamp value")
	}
	len := binary.LittleEndian.Uint32(b[6:])
	if len > maxLen {
		erroffset += 6
		return nil, erroffset, errors.New("snap length of packet is overflow")
	}
	h.ifindex = i
	h.ptype = pt
	h.timestamp = t
	h.len = len
	return h, 0, nil
}
