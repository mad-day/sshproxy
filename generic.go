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

import "bytes"
import "encoding/binary"
import "golang.org/x/crypto/ssh"
import "log"
import "errors"
import "io"

import "github.com/mad-day/sshproxy/scrambler"
import "github.com/mad-day/sshproxy/anyproto"

const any_req1 = "anyprotocolv1"

const (
	ap_conn = 0x3e
	ap_resolve = 0xF9
)

const (
	apc_ok = 0x2a
	apc_err = 0x5d
)

type anyprotocol1 struct{
	Hotness uint8
	Level   uint8
}

/*
Hotness:
	0 = This level exist on the originating client.
	1 = If the request reaches the first proxy. (Direct proxy, no mix).
	2 = First proxy-indirection
	3 = Second proxy-indirection
	4 = Third proxy-indirection
	...
*/

func ch_anyproto1(nc ssh.NewChannel){
	var cr anyprotocol1
	
	e := binary.Read(bytes.NewReader(nc.ExtraData()), binary.BigEndian,&cr)
	if e!=nil {
		log.Println("binary.Read",e)
		nc.Reject(ssh.ConnectionFailed,"Fail!")
		return
	}
	if cr.Hotness<cr.Level {
		cr.Hotness++
		buf := new(bytes.Buffer)
		e = binary.Write(buf,binary.BigEndian,cr)
		if e!=nil {
			log.Println("binary.Write",e)
			nc.Reject(ssh.ConnectionFailed,"Fail!")
			return
		}
		
		b := buf.Bytes()
		cl := selClient()
		if cl==nil {
			log.Println("No Client")
			nc.Reject(ssh.ConnectionFailed,"Fail!")
			return
		}
		ch,rq,e := cl.open(any_req1,b)
		if e!=nil {
			log.Println("cl.open",any_req1,e)
			nc.Reject(ssh.ConnectionFailed,"Fail!")
			return
		}
		go DevNullRequest(rq)
		
		ch2,rq2,e := nc.Accept()
		
		if e!=nil {
			log.Println("nc.Accept",e)
			ch.Close()
			return
		}
		go DevNullRequest(rq2)
		
		e = scrambler.Intermediate(ch2,ch)
		
		if e!=nil {
			log.Println("scrambler.Intermediate",e)
			ch.Close()
			ch2.Close()
		}
		return
	}
	
	ch2,rq2,e := nc.Accept()
	
	if e!=nil {
		log.Println("nc.Accept",e)
		return
	}
	go DevNullRequest(rq2)
	
	ech2,e := scrambler.Endpt(ch2)
	if e!=nil {
		log.Println("scrambler.Endpt",e)
		return
	}
	
	cty,e := anyproto.DecodeOneByteMessage(ech2)
	if e!=nil {
		log.Println("anyproto.DecodeOneByteMessage",e)
		return
	}
	
	switch cty{
	case ap_conn: ap1_connect(ech2,ch2)
	case ap_resolve: ap1_resolve(ech2,ch2)
	default:
		ch2.Close()
	}
}

func chopen_anyproto1(ct byte) (io.ReadWriteCloser,error){
	var cr anyprotocol1
	
	cr.Hotness = 1
	cr.Level = uint8(Level)
	
	buf := new(bytes.Buffer)
	binary.Write(buf,binary.BigEndian,cr)
	
	cl := selClient()
	if cl==nil { return nil,errors.New("No Client") }
	ch,rq,e := cl.open(any_req1,buf.Bytes()) /* send anyprotocol1 */
	if e!=nil {
		log.Println("chopen_anyproto1: cl.open",e)
		return nil,e
	}
	go DevNullRequest(rq)
	
	ech,e := scrambler.Initiator(ch)
	if e!=nil {
		log.Println("chopen_anyproto1: scrambler.Initiator",e)
		ch.Close()
		return nil,e
	}
	
	e = anyproto.EncodeOneByteMessage(ech,ct)
	if e!=nil {
		log.Println("chopen_anyproto1: anyproto.EncodeOneByteMessage",e)
		ech.Close()
		return nil,e
	}
	return ech,nil
}

