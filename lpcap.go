// Copyright (c) 2022 0x9ef. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
package lpcap

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
)

const MajorVer = 1
const MinorVer = 0

type ReaderWriterCloser interface {
	io.Reader
	io.ReaderAt
	io.Writer
	io.Closer
}

// A file format that contains captured packet data for further
// playback and tracing. Notice: It does not have any compatibility with the real PCAP format.
// The simplified version of PCAP described here
//
//	https://tools.ietf.org/id/draft-gharris-opsawg-pcap-00.html
type PCAP struct {
	h        *fileHeader
	rd       ReaderWriterCloser
	len      int32 // count of total packets
	offset   int64 // read offset of PCAP file
	isClosed bool
	lasterr  ErrorCode
	fsize    int64
	mx       *sync.RWMutex
	closeMx  *sync.Mutex
}

// Packet represents information about the captured packet
type Packet struct {
	// Interface index where frame was received
	Index uint8
	// Broadcast/Unicast/Multicast
	PacketType uint8
	// Represents the number of nanoseconds that have elapsed since 1970-01-01 00:00:00 UTC
	Timestamp uint32
	// Original length of captured packet
	Len uint32
	// Raw packet data
	Data []byte
}

type LinkType uint32

const (
	// Reserved link type
	LinkTypeNull LinkType = 0

	// Ethernet 802.3N frames
	LinkTypeEthernet2 LinkType = 2 << iota

	// Ethernet 802.11N frames
	LinkTypeEthernet80211

	// FDDI
	LinkTypeFDDI
)

// Maximum frame length that can be captured
const MaxSnapLength = 1<<14 - 1

const (
	PacketTypeBroadcast = 2 << iota // broadcast packet type
	PacketTypeUnicast               // unicast packet type
	PacketTypeMulticast             // multicast packet type
)

var packetPool = &sync.Pool{
	New: func() any {
		return make([]byte, 0, MaxSnapLength)
	},
}

// Creates a PCAP file on the specified path,
// writes the first 14 bytes of the file header and returns the PCAP
// structure and an error if the file creation failed
func Create(path string) (*PCAP, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, os.ModePerm)
	if err != nil {
		return nil, err
	}

	p := &PCAP{
		h: &fileHeader{
			mx:       lpcapmx,
			majorVer: MajorVer,
			minorVer: MinorVer,
			snapLen:  MaxSnapLength,
			link:     LinkTypeEthernet2,
		},
		rd:      f,
		len:     0,
		offset:  0,
		lasterr: ErrOk,
		mx:      new(sync.RWMutex),
		closeMx: new(sync.Mutex),
	}

	b := make([]byte, minFileSize)
	binary.LittleEndian.PutUint16(b, p.h.mx)
	binary.LittleEndian.PutUint16(b[2:], p.h.majorVer)
	binary.LittleEndian.PutUint16(b[4:], p.h.minorVer)
	binary.LittleEndian.PutUint32(b[6:], p.h.snapLen)
	binary.LittleEndian.PutUint32(b[10:], uint32(p.h.link))
	n, err := f.Write(b)
	if err != nil {
		return nil, err
	}
	p.offset += int64(n)
	p.fsize = minFileSize
	return p, nil
}

// Open a PCAP file, reads the first 14 bytes of the header,
// verifying header and returns the PCAP structure.
func Open(path string) (*PCAP, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	s, err := f.Stat()
	if err != nil {
		return nil, err
	}

	fileSize := s.Size()
	if fileSize < minFileSize {
		return nil, errors.New("file length too small, cannot read file header")
	}

	// read first 14 file header bytes and then unmarshal and parse
	b := make([]byte, minFileSize)
	n, err := f.ReadAt(b, 0)
	if err != nil {
		return nil, err
	}

	// discard PCAP file if header is invalid
	header, erroffset, err := unmarshalFileHeader(b)
	if err != nil {
		return nil, &ParseError{Offset: erroffset, Err: err}
	}

	pcap := &PCAP{
		h:       header,
		rd:      f,
		len:     0,
		offset:  int64(n),
		fsize:   fileSize,
		mx:      new(sync.RWMutex),
		closeMx: new(sync.Mutex),
	}
	return pcap, nil
}

// Reads packet header from the current offset.
// Reads first 12 bytes of packet header, determines frame size, checks timestamp,
// then reads file to size specified in packet header.
func (pcap *PCAP) ReadPacket(p *Packet) (n int, err error) {
	b := packetPool.Get().([]byte)
	b = b[:0]
	b = b[:minPacketSize]
	n, err = pcap.rd.ReadAt(b, atomic.LoadInt64(&pcap.offset))
	if err != nil {
		if err == io.EOF {
			pcap.lasterr = ErrNoMorePacket
		} else {
			pcap.lasterr = ErrRead
		}
		return 0, err
	}
	atomic.AddInt64(&pcap.offset, int64(n))

	// Unmarshal packet header with maximum snap length
	h, erroffset, err := unmarshalPacketHeader(b, pcap.h.snapLen)
	if err != nil {
		erroffset += atomic.LoadInt64(&pcap.offset)
		pcap.lasterr = ErrInvalidHeader
		return 0, &ParseError{Offset: erroffset, Err: err}
	}

	b = b[:h.len]
	n, err = pcap.rd.ReadAt(b, atomic.LoadInt64(&pcap.offset))
	if err != nil {
		if err == io.EOF {
			pcap.lasterr = ErrNoMorePacket
		} else {
			pcap.lasterr = ErrRead
		}
		return 0, err
	}
	packetPool.Put(b)

	*p = Packet{
		Index:      h.ifindex,
		PacketType: h.ptype,
		Timestamp:  h.timestamp,
		Len:        h.len,
		Data:       b,
	}
	atomic.AddInt32(&pcap.len, 1)
	atomic.AddInt64(&pcap.offset, int64(n))
	return minPacketSize + n, nil
}

// Writes timestamp, data into a PacketHeader structure and then into
// a byte array. Writes the data to a file and flushes it.
func (pcap *PCAP) WritePacket(p Packet) (n int, err error) {
	isOverflow := len(p.Data)+minPacketSize > int(pcap.h.snapLen)
	if isOverflow {
		pcap.lasterr = ErrSizeOverflow
		return 0, errors.New("cannot write packet to PCAP, because length of packet greater than snap length")
	}

	offset := 0
	b := packetPool.Get().([]byte)
	b = b[:0]
	b = b[:minPacketSize+p.Len]
	b[0] = p.Index
	b[1] = p.PacketType
	offset += 2
	binary.LittleEndian.PutUint32(b[offset:], p.Timestamp)
	offset += 4
	binary.LittleEndian.PutUint32(b[offset:], p.Len)
	offset += 4
	copy(b[offset:], p.Data)
	n, err = pcap.rd.Write(b)
	if err != nil {
		pcap.lasterr = ErrWrite
		return 0, err
	}
	atomic.AddInt64(&pcap.fsize, int64(n))
	packetPool.Put(b)
	return n, err
}

// Next return true if current readed offset less than summary file length
func (pcap *PCAP) Next() bool {
	pcap.mx.RLock()
	hasNext := pcap.offset < pcap.fsize
	pcap.mx.RUnlock()
	return hasNext
}

// Close clears the fields and then closes the file descriptor
func (pcap *PCAP) Close() error {
	pcap.closeMx.Lock()
	defer pcap.closeMx.Unlock()
	if pcap.isClosed {
		return errors.New("file is already closed")
	}
	pcap.h = nil
	pcap.len = 0
	pcap.offset = 0
	pcap.isClosed = true
	pcap.lasterr = ErrOk
	pcap.fsize = 0
	err := pcap.rd.Close()
	return err
}

// Len returns the size of the packets read from the file
func (pcap *PCAP) Len() int {
	return int(atomic.LoadInt32(&pcap.len))
}

// LinkType returns link layer of packets in the file
func (pcap *PCAP) LinkType() LinkType {
	return pcap.h.link
}

// SetLinkType setup file frame format link type
func (pcap *PCAP) SetLinkType(lt LinkType) {
	pcap.h.link = lt
}

// LastError returns the internal representation of the last error
func (pcap *PCAP) LastError() ErrorCode {
	pcap.mx.RLock()
	e := pcap.lasterr
	pcap.mx.RUnlock()
	return e
}
