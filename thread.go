//
// Copyright 2017 The Alpha-firm. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//

package webproxy

import (
	"sync/atomic"
)

var threadCount int32 = 0
var threadPool = make(chan interface{}, 200)

func aquireThread() {
	threadPool <- 0
	atomic.AddInt32(&threadCount, 1)
}

func releaseThread() {
	<- threadPool
	atomic.AddInt32(&threadCount, -1)
}

func GetRoutineCount() int32 {
	n := atomic.LoadInt32(&threadCount)
	return n
}

