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


package main

import "time"
import "github.com/lytics/confl"
import "golang.org/x/crypto/ssh"
import "github.com/mad-day/sshproxy"
import "github.com/mad-day/sshproxy/proxy"
import "github.com/armon/go-socks5"
import "fmt"
import "net"
import "os"
import "io/ioutil"

type Client struct{
	Net string `confl:"net"`
	Addr string `confl:"address"`
	User string `confl:"user"`
	Pass string `confl:"pass"`
	Hkfp string `confl:"hostkey"`
	PrivKey string `confl:"privatekey"`
	PrivKeys []string `confl:"privatekeys"`
}

func (c *Client) Transfer(s *sshproxy.Client) error{
	s.Net = c.Net
	if c.Net=="" { s.Net="tcp" }
	s.Addr = c.Addr
	s.Client.User = c.User
	s.Client.Auth = make([]ssh.AuthMethod,0,1)
	if c.Pass!="" {
		s.Client.Auth = append(s.Client.Auth,ssh.Password(c.Pass))
	}
	if c.Hkfp=="" {
		s.Client.HostKeyCallback = func (hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }
	} else if c.Hkfp[0]=='B' {
		hkfp := c.Hkfp[1:]
		s.Client.HostKeyCallback = func (hostname string, remote net.Addr, key ssh.PublicKey) error {
			if ssh.FingerprintSHA256(key)==hkfp { return nil }
			return fmt.Errorf("Wrong Key: %s, expected %s",ssh.FingerprintSHA256(key),hkfp)
		}
	}
	if c.PrivKey!="" {
		sig,e := ssh.ParsePrivateKey([]byte(c.PrivKey))
		if e!=nil { return e }
		s.Client.Auth = append(s.Client.Auth,ssh.PublicKeys(sig))
	}else if len(c.PrivKeys)!=0 {
		sigs := make([]ssh.Signer,len(c.PrivKeys))
		for i,k := range c.PrivKeys {
			sig,e := ssh.ParsePrivateKey([]byte(k))
			if e!=nil { return e }
			sigs[i] = sig
		}
		s.Client.Auth = append(s.Client.Auth,ssh.PublicKeys(sigs...))
	}
	return nil
}

type Server struct{
	Net string `confl:"net"`
	Addr string `confl:"address"`
	Pass map[string]string `confl:"passwords"`
	Auth map[string]map[string]string `confl:"auth"`
	BlankAuth string `confl:"blank"`
	NoAuth    string `confl:"noauth"`
	
	PrivKey string `confl:"privatekey"`
	PrivKeys []string `confl:"privatekeys"`
}
func (c *Server) checkAddr(usr string, na net.Addr) error {
	ip := net.IP{}
	checkable := false
	if ta,ok := na.(*net.TCPAddr); ok {
		ip = ta.IP
		checkable = true
	}
	if o,ok := c.Auth[usr]; ok {
		if n,ok2 := o["net"]; ok2 {
			if !checkable { return fmt.Errorf("Unsupported Network Addr: %v",na) }
			_,nn,e := net.ParseCIDR(n)
			if e==nil {
				if !nn.Contains(ip) {
					return fmt.Errorf("User access denied from %s",n)
				}
				return nil
			}
			nip := net.ParseIP(n)
			if !nip.Equal(ip) { return fmt.Errorf("User access denied from %s",n) }
		}
	}
	
	return nil
}
func (c *Server) checkPass(usr, pwd string) error {
	if p,ok := c.Pass[usr]; ok && p==pwd { return nil }
	if o,ok := c.Auth[usr]; ok {
		if p,ok2 := o["pass"]; ok2 && p==pwd { return nil }
		if p,ok2 := o["any"]; ok2 && (p=="pass" || p=="auth") { return nil }
	}
	if _,ok := c.Auth[usr]; c.BlankAuth=="auth" && !ok { return nil }
	
	return fmt.Errorf("Authentication failed '%s':'***'",usr)
}
func (c *Server) checkSigner(usr string, pk ssh.PublicKey) error {
	if o,ok := c.Auth[usr]; ok {
		if p,ok2 := o["hash"]; ok2 && p==ssh.FingerprintSHA256(pk) { return nil }
		if p,ok2 := o["sha256"]; ok2 && p==ssh.FingerprintSHA256(pk) { return nil }
		if p,ok2 := o["md5"]; ok2 && p==ssh.FingerprintLegacyMD5(pk) { return nil }
		if p,ok2 := o["any"]; ok2 && (p=="key" || p=="auth") { return nil }
	}
	if _,ok := c.Auth[usr]; c.BlankAuth=="auth" && !ok { return nil }
	
	return fmt.Errorf("Authentication failed '%s':%s:%s",usr,pk.Type(),ssh.FingerprintLegacyMD5(pk))
}
func (c *Server) Transfer(s *ssh.ServerConfig) error{
	if c.Net=="" { c.Net="tcp" }
	if c.PrivKey!="" {
		sig,e := ssh.ParsePrivateKey([]byte(c.PrivKey))
		if e!=nil { return e }
		s.AddHostKey(sig)
	}
	if len(c.PrivKeys)!=0 {
		for _,k := range c.PrivKeys {
			sig,e := ssh.ParsePrivateKey([]byte(k))
			if e!=nil { return e }
			s.AddHostKey(sig)
		}
	}
	s.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		e := c.checkAddr(conn.User(),conn.RemoteAddr())
		if e!=nil { return nil,e }
		e = c.checkPass(conn.User(),string(password))
		if e!=nil { return nil,e }
		return new(ssh.Permissions),nil
	}
	s.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		e := c.checkAddr(conn.User(),conn.RemoteAddr())
		if e!=nil { return nil,e }
		e = c.checkSigner(conn.User(),key)
		if e!=nil { return nil,e }
		return new(ssh.Permissions),nil
	}
	s.NoClientAuth = c.NoAuth=="on"
	
	return nil
}
func (c *Server) Serve() {
	s := new(ssh.ServerConfig)
	e := c.Transfer(s)
	if e!=nil {
		fmt.Println(e)
		os.Exit(1)
	}
	l,e := net.Listen(c.Net,c.Addr)
	if e!=nil {
		fmt.Println(e)
		os.Exit(1)
	}
	for {
		conn,e := l.Accept()
		if e!=nil { continue }
		c1,c2,c3,e := ssh.NewServerConn(conn,s)
		if e!=nil { conn.Close(); continue }
		go sshproxy.Handle(c1,c2,c3)
	}
}

type Socks struct{
	Net string `confl:"net"`
	Addr string `confl:"address"`
}
func (s *Socks) Transfer() {
	if s.Net=="" { s.Net="tcp" }
}

type Config struct{
	Clients []Client `confl:"connections"`
	Servers []Server `confl:"listeners"`
	Socks   []Socks  `confl:"socks"`
}
func (c *Config) Apply() {
	for _,cc := range c.Clients {
		spc := new(sshproxy.Client)
		e := cc.Transfer(spc)
		if e!=nil { fmt.Println(e); os.Exit(1) }
		sshproxy.Add(spc)
	}
	for _,cs := range c.Servers {
		go cs.Serve()
	}
	if len(c.Socks)!=0 {
		proco      := proxy.Config()
		prose, err := socks5.New(proco)
		if err!=nil { panic(err) }
		for _,so := range c.Socks {
			so.Transfer()
			go prose.ListenAndServe(so.Net, so.Addr)
		}
	}
}

func main() {
	var conf Config
	if len(os.Args) < 2 {
		fmt.Println("Usage:",os.Args[0],"<config-file>")
		return
	}
	fc,e := ioutil.ReadFile(os.Args[1])
	if e!=nil {
		fmt.Println("Usage:",os.Args[0],"<config-file>")
		fmt.Println(e)
		return
	}
	
	e = confl.Unmarshal(fc,&conf)
	if e!=nil {
		fmt.Println("Usage:",os.Args[0],"<config-file>")
		fmt.Println(e)
		return
	}
	
	conf.Apply()
	t := time.Tick(time.Minute)
	for { <-t }
}
