package lpcap

import (
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestReadPacket(t *testing.T) {
	pcap, err := Create("0pcap")
	if err != nil {
		t.Fatal(err)
	}
	defer pcap.Close()

	data := make([]byte, 128)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	p := Packet{
		Index:      4,
		PacketType: PacketTypeBroadcast,
		Timestamp:  uint32(time.Now().UnixNano()),
		Len:        uint32(len(data)),
		Data:       data,
	}

	n, err := pcap.WritePacket(p)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, minPacketSize+len(data), n)

	pp := new(Packet)
	n, err = pcap.ReadPacket(pp)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, data, p.Data)
	assert.Equal(t, uint8(4), p.Index)
	assert.Equal(t, uint8(PacketTypeBroadcast), p.PacketType)
	assert.Equal(t, uint32(128), p.Len)
}

func BenchmarkReadPacket(b *testing.B) {
	pcap, err := Create("0pcap")
	if err != nil {
		b.Fatal(err)
	}
	defer pcap.Close()

	data := make([]byte, 128)
	if _, err := rand.Read(data); err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		n, err := pcap.WritePacket(Packet{
			Index:      0x4,
			PacketType: PacketTypeBroadcast,
			Timestamp:  uint32(time.Now().UnixNano()),
			Len:        uint32(len(data)),
			Data:       data,
		})
		if err != nil {
			b.Fatal(err, n)
		}
	}
	b.ResetTimer()

	p := new(Packet)
	for i := 0; i < b.N; i++ {
		n, err := pcap.ReadPacket(p)
		if err != nil {
			b.Fatal(err, n)
		}
	}
}

func BenchmarkWritePacket(b *testing.B) {
	pcap, err := Create("0pcap")
	if err != nil {
		b.Fatal(err)
	}
	defer pcap.Close()

	data := make([]byte, 128)
	if _, err := rand.Read(data); err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		n, err := pcap.WritePacket(Packet{
			Index:      0x4,
			PacketType: PacketTypeBroadcast,
			Timestamp:  uint32(time.Now().UnixNano()),
			Len:        uint32(len(data)),
			Data:       data,
		})
		if err != nil {
			b.Fatal(err, n)
		}
	}
}
