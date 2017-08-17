//
// Copyright 2017 The Alpha-firm. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//

package webproxy

import (
	"net"
	"time"
	"net/http"
	"bufio"
	"strings"
	"crypto/tls"
	"io/ioutil"
)

type Session struct {
	sessionData  interface{}
	requestBody  *body
	responseBody *body
	conClient    net.Conn
	conServer    net.Conn
	request      *http.Request
	response     *http.Response
}

func NewSession(conn net.Conn) *Session {
	return &Session{conClient : conn}
}

func (this *Session)GetLocalData() interface{} {
	return this.sessionData
}

func (this *Session)SetLocalData(data interface{}) {
	this.sessionData = data
}

// This is a go routine
func (this *Session) run(p *Proxy) {

	//aquireThread()
	//defer releaseThread()

	defer this.close()

	// Read request from client
	err := this.readRequest()
	if err != nil {
		return
	}

	host := this.GetHost()

	if !strings.Contains(host, ":") {
		host += ":80"
	}

	conRemote, err := net.DialTimeout("tcp", host, time.Second * 10)
	if err != nil {
		return
	}

	this.conServer = conRemote

	if strings.Contains(host, ":443") {
		this.handleTLSSession(p)
	} else {
		this.handleSession(p)
	}
}

func (this *Session) close() {
	if this.conServer != nil {
		this.conServer.Close()
	}

	if this.conClient != nil {
		this.conClient.Close()
	}
}

func (this *Session) readRequest() (err error) {

	r := bufio.NewReader(this.conClient)
	this.conClient.SetReadDeadline(time.Now().Add(time.Second * 10))
	this.request, err = http.ReadRequest(r)
	return err
}

//Send request to server and get a response
func (this *Session) doRequest() error {

	//Transfer request to remote server
	err := this.request.Write(this.conServer)

	if err != nil {
		return err
	}

	//Request has been sent to server, get the response
	reader := bufio.NewReader(this.conServer)
	this.response, err = http.ReadResponse(reader, this.request)
	return err
}

//Flush the response to client
func (this *Session) doResponse() error {

	return this.response.Write(this.conClient)
}

//flush function run in a infinite loop until an error occur
func flush(r, w net.Conn, c chan<- error) {

	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			w.Write(buf[0: n])
		}
		if err != nil {
			c <- err
			break
		}
	}

	close(c)
}

//doTransfer start two go routines to transfer data between client and server
func (this *Session) doTransfer()  {

	cChan := make(chan error, 1)
	sChan := make(chan error, 1)

	go flush(this.conClient, this.conServer, cChan)
	go flush(this.conServer, this.conClient, sChan)

	select {
	case <- cChan :
		break
	case <- sChan :
		break
	}
}

func (this *Session) handleTLSSession(p *Proxy) {

	//Tell the client TLS connection has been established
	//fmt.Println("Tunnel to :", session.GetHost())
	_, err := this.conClient.Write([]byte("HTTP/1.0 200 Connection Established\r\n\r\n"))
	if err != nil {
		return
	}

	//If cert file is not provided, we do nothing but transfer the data
	//between client and remote server
	if err = loadRootCert(); err != nil {
		this.doTransfer()
		return
	}

	//Starting decrypt the TLS session
	config := &tls.Config{}
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = createCertForHost(this.GetHost())
	if err != nil {
		return
	}

	//Set the connection as TLS connection
	this.conClient = tls.Server(this.conClient, config)
	this.conServer = tls.Client(this.conServer, &tls.Config{InsecureSkipVerify: true})

	for {

		if err = this.readRequest(); err != nil {
			return
		}
		this.handleSession(p)
	}
}

func (this *Session) handleSession(p *Proxy) {

	if p.sn != nil {
		p.sn.BeforeRequest(this)
	}
	err := this.doRequest()
	if err != nil || this.response == nil {
		return
	}
	if p.sn != nil {
		p.sn.BeforeResponse(this)
	}
	this.doResponse()

	this.requestBody  = nil
	this.responseBody = nil
}

func (this *Session) GetHost() string {

	if this.request == nil {
		return ""
	}
	return this.request.Host
}

func (this *Session) GetRequestHead() http.Header {

	if this.request == nil {
		return nil
	}
	return this.request.Header
}

func (this *Session) GetResponseHead() http.Header {

	if this.response == nil {
		return nil
	}
	return this.response.Header
}

func (this *Session) GetMethod() string {

	if this.request == nil {
		return ""
	}
	return this.request.Method
}

func (this *Session) GetStatus() string {

	if this.response == nil {
		return ""
	}
	return this.response.Status
}

func (this *Session) GetRequestProto() string {

	if this.request == nil {
		return ""
	}
	return this.request.Proto
}

func (this *Session) GetResponseProto() string {

	if this.response == nil {
		return ""
	}
	return this.response.Proto
}

func (this *Session) GetRequestURL() string {

	if this.request == nil {
		return ""
	}
	return this.request.URL.String()
}

func (this *Session) GetRequestBody() string {

	if this.request.ContentLength == 0 {
		return ""
	}

	if this.requestBody == nil {
		buf, _ := ioutil.ReadAll(this.request.Body)
		this.requestBody = newBody(buf)
		this.request.Body = this.requestBody
	}

	return string(this.requestBody.getContent())
}

func (this *Session) SetRequestBody(body string) {

	if len(body) > 0 && this.requestBody != nil {
		buf := []byte(body)
		this.requestBody.setContent(buf)

		//If ContentLength < 0, maybe chuncked body, Content-Length field
		//will not  be included in header, so we ignore it
		if this.request.ContentLength >= 0 {
			this.request.ContentLength = int64(len(buf))
		}
	}
}

//Call this func if it is really necessary, because of memory
//consuming for large response
func (this *Session) GetResponseBody() string {

	if this.response.ContentLength == 0 {
		return ""
	}

	if this.responseBody == nil {
		buf, _ := ioutil.ReadAll(this.response.Body)
		this.responseBody = newBody(buf)
		this.response.Body = this.responseBody
	}

	return string(this.responseBody.getContent())
}

func (this *Session) SetResponseBody(body string) {

	if len(body) > 0 && this.responseBody != nil {

		buf := []byte(body)
		this.responseBody.setContent(buf)

		//If ContentLength < 0, maybe chuncked body, Content-Length field
		//will not  be included in header, so we ignore it
		if this.response.ContentLength >= 0 {
			this.response.ContentLength = int64(len(buf))
		}
	}
}

func (this *Session) GetRequestEncoding() string {

	if this.request != nil {
		encoding := this.request.Header["Content-Encoding"]
		if encoding != nil {
			return encoding[0]
		}
	}

	return ""
}

func (this *Session) GetResponseEncoding() string {

	if this.response != nil {
		encoding := this.response.Header["Content-Encoding"]
		if encoding != nil {
			return encoding[0]
		}
	}

	return ""
}

func (this *Session) GetResponseType() string {

	if this.request != nil {
		types := this.response.Header["Content-Type"]
		if types != nil {
			return types[0]
		}
	}

	return ""
}

