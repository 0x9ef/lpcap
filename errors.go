// Copyright (c) 2022 0x9ef. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
package lpcap

import (
	"fmt"
	"strconv"
)

// ParseError represents the position where the error was found
// and the typical error message.
type ParseError struct {
	Offset int64
	Err    error
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("at: %d pos, err: %s", e.Offset, e.Err)
}

func (e *ParseError) Unwrap() error {
	return e.Err
}

// ErrorCode represents an internal integer code of error insead of string message
type ErrorCode int

const (
	ErrOk   ErrorCode = 0
	ErrRead ErrorCode = 1 << iota
	ErrWrite
	ErrInvalidHeader
	ErrSizeOverflow
	ErrNoMorePacket
)

func (e ErrorCode) Error() string {
	switch e {
	case ErrOk:
		return "Ok"
	case ErrRead:
		return "Read Error"
	case ErrWrite:
		return "Write Error"
	case ErrInvalidHeader:
		return "Invalid Packet Header"
	case ErrSizeOverflow:
		return "Size Overflow"
	case ErrNoMorePacket:
		return "No More Packets"
	}
	return strconv.Itoa(int(e))
}
