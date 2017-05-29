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

func channel(nc ssh.NewChannel){
	{
		switch(nc.ChannelType()){
		case any_req1:  ch_anyproto1(nc)
		}
	}
	nc.Reject(ssh.UnknownChannelType,"Unknown channel type!")
}
func request(r *ssh.Request){
	if r.WantReply { r.Reply(false,nil) }
}

func channel2(conn ssh.Conn,nc <-chan ssh.NewChannel){
	for n := range nc {
		go channel(n)
	}
}
func request2(conn ssh.Conn,reqs <-chan *ssh.Request){
	for r := range reqs {
		go request(r)
	}
}


var Level int = 4

func Handle(conn ssh.Conn, nc <-chan ssh.NewChannel, reqs <-chan *ssh.Request){
	go channel2(conn,nc)
	go request2(conn,reqs)
}

func DevNullRequest(reqs <-chan *ssh.Request){
	for r := range reqs { if r.WantReply { r.Reply(false,nil) } }
}


func DevNullChannel(nc <-chan ssh.NewChannel){
	for c := range nc { c.Reject(ssh.Prohibited,"no") }
}

