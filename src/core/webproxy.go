//
// Copyright 2017 The Alpha-firm. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//

package webproxy

import (
	"fmt"
	"net"
	"os"
	"time"
	"net/http"
	"bufio"
	"strings"
	"errors"
	"crypto/tls"
)

type Session struct {
	request   *http.Request
	response  *http.Response
	conClient net.Conn
	conServer net.Conn
	requestContent  *buffer
	responseContent *buffer
}

type Proxy struct {
	port     int
	sn       Sniffer
}

func newSession(conn net.Conn) *Session {
	return &Session{conClient : conn}
}

// This is a go routine
func (session *Session) run(p *Proxy) {

	//aquireThread()
	//defer releaseThread()

	defer session.close()

	// Read request from client
	err := session.readRequest()
	if err != nil {
		return
	}

	host := session.GetHost()

	if !strings.Contains(host, ":") {
		host += ":80"
	}

	conRemote, err := net.DialTimeout("tcp", host, time.Second * 10)
	if err != nil {
		return
	}

	session.conServer = conRemote

	if strings.Contains(host, ":443") {
		session.handleTLSSession(p)
	} else {
		session.handleSession(p)
	}
}

func (session *Session) close() {
	if session.conServer != nil {
		session.conServer.Close()
	}

	if session.conClient != nil {
		session.conClient.Close()
	}

	session.request         = nil
	session.response        = nil
	session.requestContent  = nil
	session.responseContent = nil
}

func (session *Session) readRequest() (err error) {

	r := bufio.NewReader(session.conClient)
	session.conClient.SetReadDeadline(time.Now().Add(time.Second * 10))
	session.request, err = http.ReadRequest(r)
	return err
}

//Send request to server and get a response
func (session *Session) doRequest() error {

	if session.request == nil {
		return errors.New("No request is available.")
	}

	//Transfer request to remote server
	var err error
	if session.requestContent != nil {
		_, err = session.requestContent.flush(session.conServer)
	} else {
		err = session.request.Write(session.conServer)
	}

	if err != nil {
		return err
	}

	//Request has been sent to server, get the response
	reader := bufio.NewReader(session.conServer)
	session.response, err = http.ReadResponse(reader, session.request)
	return err
}

//Flush the response to client
func (session *Session) doResponse() error {

	if session.response == nil {
		return errors.New("No response is available.")
	}

	var err error
	if session.responseContent != nil {
		_, err = session.responseContent.flush(session.conClient)
	} else {
		err = session.response.Write(session.conClient)
	}

	return err
}

//This function run in a infinite loop until nothing to flush when timeout
func flush(r, w net.Conn, timeout time.Duration) int {

	buf := make([]byte, 4096)
	var count, n = 0, 0
	for {
		r.SetReadDeadline(time.Now().Add(timeout))
		n, _ = r.Read(buf)
		if n > 0 {
			w.Write(buf[0: n])
			count += n
		} else {
			break
		}
	}

	return count
}

func (session *Session) handleTLSSession(p *Proxy) {

	//Tell the client TLS connection has been established
	//fmt.Println("Tunnel to :", session.GetHost())
	_, err := session.conClient.Write([]byte("HTTP/1.0 200 Connection Established\r\n\r\n"))
	if err != nil {
		return
	}

	//If cert file is not provided, we do nothing but transfer the data
	//between client and remote server
	if err = loadRootCert(); err != nil {
		for {
			//Start transfer the binary stream between client and server
			n := flush(session.conClient, session.conServer, time.Millisecond*200)
			if n <= 0 {
				break
			}

			flush(session.conServer, session.conClient, time.Millisecond*600)
		}

		return
	}

	//Starting decrypt the TLS session
	config := &tls.Config{}
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = createCertForHost(session.GetHost())
	if err != nil {
		fmt.Println(err)
		return
	}

	//Set the connection as TLS connection
	session.conClient = tls.Server(session.conClient, config)
	session.conServer = tls.Client(session.conServer, &tls.Config{InsecureSkipVerify: true})

	for {

		if err = session.readRequest(); err != nil {
			return
		}
		session.handleSession(p)
	}
}

func (session *Session) handleSession(p *Proxy) {

	if p.sn != nil {
		p.sn.BeforeRequest(session)
	}
	err := session.doRequest()
	if err != nil || session.response == nil {
		return
	}
	if p.sn != nil {
		p.sn.BeforeResponse(session)
	}
	session.doResponse()

	session.requestContent = nil
	session.responseContent = nil
}

func (session *Session) keepAlive() bool {

	header := session.GetRequestHead()
	if header == nil {
		return false
	}

	//We only check keep-alive flag on client side
	for k, v := range header {
		if strings.Contains(k, "Connection") &&
			v != nil && strings.Contains(v[0], "keep-alive") {
			return true
		}
	}

	return false
}

func (session *Session) GetHost() string {

	if session.request == nil {
		return ""
	}
	return session.request.Host
}

func (session *Session) GetRequestLength() int64 {

	if session.request == nil {
		return 0
	}
	return session.request.ContentLength
}

func (session *Session) GetResponseLength() int64 {

	if session.response == nil {
		return 0
	}
	return session.response.ContentLength
}

func (session *Session) GetRequestHead() http.Header {

	if session.request == nil {
		return nil
	}
	return session.request.Header
}

func (session *Session) GetResponseHead() http.Header {

	if session.response == nil {
		return nil
	}
	return session.response.Header
}

func (session *Session) GetMethod() string {

	if session.request == nil {
		return ""
	}
	return session.request.Method
}

func (session *Session) GetStatus() string {

	if session.response == nil {
		return ""
	}
	return session.response.Status
}

func (session *Session) GetRequestProto() string {

	if session.request == nil {
		return ""
	}
	return session.request.Proto
}

func (session *Session) GetResponseProto() string {

	if session.response == nil {
		return ""
	}
	return session.response.Proto
}

func (session *Session) GetRequestURL() string {

	if session.request == nil {
		return ""
	}
	return session.request.URL.String()
}

func (session *Session) GetRequestContent() []byte {
	if session.request == nil {
		return nil
	}

	if session.requestContent == nil {
		session.requestContent = newBuffer()
		session.request.Write(session.requestContent)
	}

	return session.requestContent.getContent()
}

//Call this func if it is really necessary, because of memory
//consuming for large response
func (session *Session) GetResponseContent() []byte {

	if session.response == nil {
		return nil
	}

	if session.responseContent == nil {
		session.responseContent = newBuffer()
		session.response.Write(session.responseContent)
	}

	return session.responseContent.getContent()
}

func (session *Session) GetResponseType() string {

	contentType := ""
	if session.response != nil {

		ct := session.response.Header["Content-Type"]
		if ct != nil {
			for _, v := range ct {
				contentType += v
			}
		}
	}

	return contentType
}

func NewProxy(p int, s Sniffer) *Proxy {
	return &Proxy{port : p, sn : s}
}

func (p *Proxy) Start() {

	//Listen on all available interfaces to allow remote access
	fmt.Println("Webproxy start listening... Port =", p.port)
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", p.port))
	defer l.Close()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	for {
		conn, _ := l.Accept()
		if conn != nil {
			//incoming connection, start a session
			session := newSession(conn)
			go session.run(p)
		}
	}
}
