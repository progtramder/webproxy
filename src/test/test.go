//
// Copyright 2017 The Alpha-firm. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//

package main

import (
	"fmt"
	"core"
)

type TestSniffer struct {

}

func (*TestSniffer) BeforeRequest(s *webproxy.Session) {
	fmt.Println(s.GetMethod(), s.GetRequestURL())
	for k, v := range s.GetRequestHead() {
		if v != nil {
			fmt.Println(k, v)
		}
	}

	fmt.Println("")
}

func (*TestSniffer) BeforeResponse(s *webproxy.Session) {
	fmt.Println(s.GetResponseProto(), s.GetStatus())
	for k, v := range s.GetResponseHead() {
		if v != nil {
			fmt.Println(k, v)
		}
	}

	fmt.Println("")
}

func main() {
	proxy := webproxy.NewProxy(9999, &TestSniffer{})
	proxy.Start()
}
