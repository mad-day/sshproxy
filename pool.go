/*
MIT License

Copyright (c) 2017 Simon Schmidt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/


package sshproxy

import "math/rand"
import "golang.org/x/crypto/ssh"
import "net"
import "io"
import "sync"

type Client struct{
	Client ssh.ClientConfig
	Net string
	Addr string
	err error
	conn ssh.Conn
	nc <-chan ssh.NewChannel
	reqs <-chan *ssh.Request
	mutex sync.Mutex
}
func (c *Client) handler(){
	go DevNullChannel(c.nc)
	DevNullRequest(c.reqs)
	c.conn.Close()
	c.err = io.EOF
}
func (c *Client) getConn() (ssh.Conn,error){
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.err!=nil || c.conn==nil {
		co,e := net.Dial(c.Net,c.Addr)
		if e!=nil { return nil,e }
		st,snc,sr,e := ssh.NewClientConn(co,c.Addr,&c.Client)
		if e!=nil { return nil,e }
		c.err = nil
		c.conn = st
		c.nc = snc
		c.reqs = sr
		go c.handler()
		return st,nil
	}
	return c.conn,nil
}
func (c *Client) send(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	cc,e := c.getConn()
	if e!=nil { c.err = e; return false,nil,e }
	return cc.SendRequest(name,wantReply,payload)
}
func (c *Client) open(ct string, data []byte) (ch ssh.Channel, rq <-chan *ssh.Request, er error) {
	cc,e := c.getConn()
	if e!=nil { c.err = e; er=e; return }
	return cc.OpenChannel(ct,data)
}

var x []*Client = nil

func Add(c *Client){
	x = append(x,c)
}

func selClient() *Client {
	xr := x
	xl := len(xr)
	if xl==0 { return nil }
	return xr[rand.Int31n(int32(xl))]
}

