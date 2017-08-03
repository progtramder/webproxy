//
// Copyright 2017 The Alpha-firm. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//

package webproxy

import "io"

type buffer struct {
	b   []byte
	pos int
}

func newBuffer() *buffer {
	return &buffer{b : make([]byte, 4096), pos : 0}
}

func (buf *buffer) Write(p []byte) (n int, err error) {
	n = len(p)
	if n > len(buf.b) - buf.pos {
		tmpBuf := make([]byte, (1 + n / 4096) * 4096 + len(buf.b))
		copy(tmpBuf, buf.b[0 : buf.pos])
		buf.b = tmpBuf
	}

	copy(buf.b[buf.pos : ], p[0 : n])
	buf.pos += n

	return n, nil
}

func (buf *buffer) getContent() []byte {
	return buf.b[0 : buf.pos]
}

func (buf *buffer) flush(writer io.Writer) (int, error) {
	return writer.Write(buf.b[0: buf.pos])
}
