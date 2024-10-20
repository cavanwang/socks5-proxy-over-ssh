package main

import (
	"io"
)

type ReaderWithBegin struct {
	beginBytes []byte
	r          io.Reader
}

func NewReaderWithBegin(beginBytes []byte, reader io.Reader) *ReaderWithBegin {
	r := &ReaderWithBegin{r: reader}
	r.beginBytes = make([]byte, len(beginBytes))
	copy(r.beginBytes, beginBytes)
	return r
}

func (r *ReaderWithBegin) Read(b []byte) (n int, err error) {
	if len(b) <= len(r.beginBytes) {
		copy(b, r.beginBytes)
		r.beginBytes = r.beginBytes[:len(b)]
		return len(b), nil
	}

	if len(r.beginBytes) > 0 {
		n = copy(b, r.beginBytes)
		r.beginBytes = nil
		return n, nil
	}

	return r.r.Read(b)
}
