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

func (this *body) Read(p []byte) (int, error) {

	if this.N >= len(this.bf) || this.closed == true {
		return 0, io.EOF
	}

	n := copy(p, this.bf[this.N : ])
	this.N += n

	return n, nil
}

func (this *body) Close() error {
	this.closed = true
	return nil
}

func (this *body) getContent() []byte {
	return this.bf
}

func (this *body) setContent(buf []byte) {
	this.bf = buf
	this.N  = 0
}
