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

import "github.com/davecgh/go-xdr/xdr2"
import "golang.org/x/crypto/ssh"
import "net"
import "errors"
import "log"
import "io"

func ap1_resolve(ech2 io.ReadWriteCloser, ch2 ssh.Channel){
	enc := xdr.NewEncoder(ech2)
	dec := xdr.NewDecoder(ech2)
	s,_,e := dec.DecodeString()
	if e!=nil {
		log.Println("xdr2.DecodeString",e)
		ch2.Close()
		return
	}
	
	addr, e := net.ResolveIPAddr("ip", s)
	if e!=nil {
		enc.EncodeBool(false)
		enc.EncodeOpaque(make([]byte,16))
	}else{
		enc.EncodeBool(true)
		enc.EncodeOpaque([]byte(addr.IP))
	}
	ch2.Close()
}

func Resolve(name string) (net.IP, error){
	ech2,e := chopen_anyproto1(ap_resolve)
	if e!=nil { return nil,e }
	
	enc := xdr.NewEncoder(ech2)
	dec := xdr.NewDecoder(ech2)
	
	_,e = enc.EncodeString(name)
	if e!=nil { return nil,e }
	
	ok,_,e := dec.DecodeBool()
	if e!=nil { return nil,e }
	ipa,_,e := dec.DecodeOpaque()
	if e!=nil { return nil,e }
	
	ech2.Close()
	
	if !ok {
		return nil,errors.New("No such name!")
	}
	
	switch len(ipa) {
	case 4,16: return net.IP(ipa),e
	default: return nil,errors.New("Invalid IP address format!")
	}
	panic("unreachable")
}

