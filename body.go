// Copyright 2017 The Alpha-firm. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//

package webproxy

import "io"

type body struct {
	b      []byte
	n      int
	closed bool
}

func newBody(buf []byte) *body {
	return &body{b : buf}
}

func (this *body) Read(p []byte) (int, error) {

	if this.n >= len(this.b) || this.closed == true {
		return 0, io.EOF
	}

	n := copy(p, this.b[this.n : ])
	this.n += n

	return n, nil
}

func (this *body) Close() error {
	this.closed = true
	return nil
}

func (this *body) getContent() []byte {
	return this.b
}

func (this *body) setContent(buf []byte) {
	this.b = buf
	this.n  = 0
}
