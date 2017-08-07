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
	"crypto/tls"
	"io/ioutil"
)

type Session struct {
	request      *http.Request
	response     *http.Response
	conClient    net.Conn
	conServer    net.Conn
	requestBody  *body
	responseBody *body
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
}

func (session *Session) readRequest() (err error) {

	r := bufio.NewReader(session.conClient)
	session.conClient.SetReadDeadline(time.Now().Add(time.Second * 10))
	session.request, err = http.ReadRequest(r)
	return err
}

//Send request to server and get a response
func (session *Session) doRequest() error {

	//Transfer request to remote server
	err := session.request.Write(session.conServer)

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

	return session.response.Write(session.conClient)
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

	session.requestBody  = nil
	session.responseBody = nil
}

func (session *Session) GetHost() string {

	if session.request == nil {
		return ""
	}
	return session.request.Host
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

func (session *Session) GetRequestBody() string {

	if session.request.ContentLength == 0 {
		return ""
	}

	if session.requestBody == nil {
		buf, _ := ioutil.ReadAll(session.request.Body)
		session.requestBody = newBody(buf)
		session.request.Body = session.requestBody
	}

	return string(session.requestBody.getContent())
}

func (session *Session) SetRequestBody(body string) {

	if len(body) > 0 && session.requestBody != nil {
		buf := []byte(body)
		session.requestBody.setContent(buf)

		//If ContentLength < 0, maybe chuncked body, Content-Length field
		//will not  be included in header, so we ignore it
		if session.request.ContentLength >= 0 {
			session.request.ContentLength = int64(len(buf))
		}
	}
}

//Call this func if it is really necessary, because of memory
//consuming for large response
func (session *Session) GetResponseBody() string {

	if session.response.ContentLength == 0 {
		return ""
	}

	if session.responseBody == nil {
		buf, _ := ioutil.ReadAll(session.response.Body)
		session.responseBody = newBody(buf)
		session.response.Body = session.responseBody
	}

	return string(session.responseBody.getContent())
}

func (session *Session) SetResponseBody(body string) {

	if len(body) > 0 && session.responseBody != nil {

		buf := []byte(body)
		session.responseBody.setContent(buf)

		//If ContentLength < 0, maybe chuncked body, Content-Length field
		//will not  be included in header, so we ignore it
		if session.response.ContentLength >= 0 {
			session.response.ContentLength = int64(len(buf))
		}
	}
}

func (session *Session) GetRequestEncoding() string {

	if session.request != nil {
		encoding := session.request.Header["Content-Encoding"]
		if encoding != nil {
			return encoding[0]
		}
	}

	return ""
}

func (session *Session) GetResponseEncoding() string {

	if session.response != nil {
		encoding := session.response.Header["Content-Encoding"]
		if encoding != nil {
			return encoding[0]
		}
	}

	return ""
}

func (session *Session) GetResponseType() string {

	if session.request != nil {
		types := session.response.Header["Content-Type"]
		if types != nil {
			return types[0]
		}
	}

	return ""
}

func NewProxy(p int, s Sniffer) *Proxy {
	return &Proxy{port : p, sn : s}
}

func (p *Proxy) Start() {

	//Listen on all available interfaces to allow remote access
	fmt.Println("Webproxy start listening... Port =", p.port)
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", p.port))
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

	l.Close()
}
