//
// Copyright 2017 The Alpha-firm. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//

package webproxy

import (
	"sync/atomic"
	"fmt"
)

var threadCount int32 = 0
var threadPool = make(chan interface{}, 200)

func aquireThread() {
	threadPool <- 0
	atomic.AddInt32(&threadCount, 1)
	fmt.Println("Aquire new thread, remaining :", atomic.LoadInt32(&threadCount))
}

func releaseThread() {
	<- threadPool
	atomic.AddInt32(&threadCount, -1)
	fmt.Println("Release thread, remaining :", atomic.LoadInt32(&threadCount))
}
