//
// Copyright 2017 by Progtramder. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//

package webproxy

import (
	"os"
	"net"
	"fmt"
)

type Proxy struct {
	port     int
	sn       Sniffer
}

func NewProxy(p int, s Sniffer) *Proxy {
	return &Proxy{port : p, sn : s}
}

func (this *Proxy) Start() {

	//Listen on all available interfaces to allow remote access
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", this.port))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	for {
		conn, _ := l.Accept()
		if conn != nil {
			//incoming connection, start a session
			session := NewSession(conn)
			go session.run(this)
		}
	}

	l.Close()
}

