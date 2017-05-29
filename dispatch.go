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

import "golang.org/x/crypto/ssh"
import "io"

func ch_proxy_req(ch ssh.Channel, rq *ssh.Request) {
	b,_ := ch.SendRequest(rq.Type,true,rq.Payload)
	rq.Reply(b,[]byte{})
}
func ch_proxy_reqs(ch ssh.Channel, rq <-chan *ssh.Request){
	for r := range rq {
		if r.WantReply {
			go ch_proxy_req(ch,r)
		}else{
			ch.SendRequest(r.Type,false,r.Payload)
		}
	}
}

func ch_proxy_copy(src ssh.Channel,dst ssh.Channel){
	b := make([]byte,1<<13)
	for {
		n,e := src.Read(b)
		if e==io.EOF {
			dst.CloseWrite()
			return
		}
		if n>0 {
			dst.Write(b[:n])
		}
	}
}

func ch_proxy_copyin(src io.Reader,dst ssh.Channel){
	b := make([]byte,1<<13)
	for {
		n,e := src.Read(b)
		if e==io.EOF {
			dst.CloseWrite()
			return
		}
		if n>0 {
			dst.Write(b[:n])
		}
	}
}
func ch_proxy_copyin2(src io.Reader,dst io.Writer, ch ssh.Channel){
	b := make([]byte,1<<13)
	for {
		n,e := src.Read(b)
		if e==io.EOF {
			ch.CloseWrite()
			return
		}
		if n>0 {
			dst.Write(b[:n])
		}
	}
}
func ch_proxy_copyout(src ssh.Channel,dst io.WriteCloser){
	b := make([]byte,1<<13)
	for {
		n,e := src.Read(b)
		if e==io.EOF {
			dst.Close()
			return
		}
		if n>0 {
			dst.Write(b[:n])
		}
	}
}
func ch_proxy_copyout2(src io.Reader,dst io.WriteCloser){
	b := make([]byte,1<<13)
	for {
		n,e := src.Read(b)
		if e==io.EOF {
			dst.Close()
			return
		}
		if n>0 {
			dst.Write(b[:n])
		}
	}
}

func ch_proxy_eat(src io.Reader){
	b := make([]byte,1<<13)
	for {
		_,e := src.Read(b)
		if e==io.EOF {
			return
		}
	}
}
