//
// Copyright 2017 The Alpha-firm. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//

package webproxy

import "io"

type body struct {
	bf     []byte
	N      int
	closed bool
}

func newBody(buf []byte) *body {
	return &body{bf : buf}
}

func (b *body) Read(p []byte) (int, error) {

	if b.N >= len(b.bf) || b.closed == true {
		return 0, io.EOF
	}

	n := copy(p, b.bf[b.N : ])
	b.N += n

	return n, nil
}

func (b *body) Close() error {
	b.closed = true
	return nil
}

func (b *body) getContent() []byte {
	return b.bf
}

func (b *body) setContent(buf []byte) {
	b.bf = buf
	b.N  = 0
}

type buffer struct {
	B []byte
	N int
}
