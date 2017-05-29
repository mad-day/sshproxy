package main

import "github.com/armon/go-socks5"

import "github.com/mad-day/sshproxy"
import "github.com/mad-day/sshproxy/proxy"
import "golang.org/x/crypto/ssh"
import "flag"
import "net"
import "log"

/*
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINpcyTqtBS2t3a2W9zVK3qqHZ1WLvKmUaIEJjuczR6oIoAoGCCqGSM49
AwEHoUQDQgAEAuRnSSLzz16HITwg8UdmEgFQkBBI95EEvhx0t2ILmAe15inqMKC9
rwrLQ3JQB+bAB0QMcPvPawOSy6avWA5y4A==
-----END EC PRIVATE KEY-----
*/
const pk = `-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQCju6QhIVxGoZrw8lM1rAR2JII00fNbAVogQ4GDEUCCrrsc2Z5c
x2jLewr9Wbi6UCfGMYdz+jORiSpk4qRtuxOC93zwkRSyXsdz6a81267n0vL+72h4
WyWyBgpGxLUE0WnQO5uty/gOkL52UvQA3nz9wgmzM+dN3AKSP+JkqwXbGwIVAO+P
7hjNGz9GubCrN5GWdWeFW0MzAoGADNg8ihj/Z6J3RwDiU06FqxtofNkZF6ImssZG
G6v5oe36cLSeXFdUJJbcozXaCbIGzV1pyyw0wEtzPobAtlfZak6NnEv6a4fvZlim
E7mJjmqoxfHvfGQQFa2cXAk+JCCEZvXMVnPmcrjL3iDWwkdv3dJq0jXJ+A3+9Sp+
u9WzkW8CgYAtDs7Yv06P3t1DNPU9U3vf8eKBXznBKllummdoq350vIwgoqWL4AU5
/8WXCLv2wj6i0NbVP7Sxh6KTf+V4mZtkb3ljv+vyYhTKPnFZ8y794Eenw7Ymv1/P
95Jcb1s4KmV3ZG9lmIa5dIb/XxKNCWL2pLMAu/PRe++ySfcmlGOpvQIVAI/5auF8
0QOtOZHIOF/qYQC8SQb8
-----END DSA PRIVATE KEY-----
`

func ssh_auth (conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	return new(ssh.Permissions),nil
}

func ssh_key(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }

var Client sshproxy.Client
var Server ssh.ServerConfig

var server = flag.Int("server", 0, "server")

func server10(){
	conf := &socks5.Config{}
	server, err := socks5.New(conf)
	if err != nil {
		panic(err)
	}
	
	// Create SOCKS5 proxy on localhost port 8000
	if err := server.ListenAndServe("tcp", "127.0.0.1:8000"); err != nil {
		panic(err)	
	}
}

func server1(){
	Client.Addr = "127.0.0.1:8001"
	sshproxy.Add(&Client)
	conf := proxy.Config()
	
	server, err := socks5.New(conf)
	if err != nil {
		panic(err)
	}
	
	// Create SOCKS5 proxy on localhost port 8000
	if err := server.ListenAndServe("tcp", "127.0.0.1:8000"); err != nil {
		panic(err)	
	}
}

func servessh(n net.Listener){
	for{
		c,e := n.Accept()
		if e!=nil { return }
		cc,nc,rr,e := ssh.NewServerConn(c,&Server)
		if e!=nil { c.Close(); continue }
		sshproxy.Handle(cc,nc,rr)
	}
}

func server2(){
	Client.Addr = "127.0.0.1:8002"
	sshproxy.Add(&Client)
	l,e := net.Listen("tcp","127.0.0.1:8001")
	if e!=nil { panic(e) }
	servessh(l)
}
func server3(){
	Client.Addr = "127.0.0.1:8003"
	sshproxy.Add(&Client)
	l,e := net.Listen("tcp","127.0.0.1:8002")
	if e!=nil { panic(e) }
	servessh(l)
}
func server4(){
	Client.Addr = "127.0.0.1:8004"
	sshproxy.Add(&Client)
	l,e := net.Listen("tcp","127.0.0.1:8003")
	if e!=nil { panic(e) }
	servessh(l)
}

func server5(){
	l,e := net.Listen("tcp","127.0.0.1:8004")
	if e!=nil { panic(e) }
	servessh(l)
}


func main(){
	Client.Net = "tcp"
	Server.PasswordCallback = ssh_auth
	Client.Client.User = "pirco"
	Client.Client.Auth = append(Client.Client.Auth,ssh.Password("secret123"))
	Client.Client.HostKeyCallback = ssh_key
	s,e := ssh.ParsePrivateKey([]byte(pk))
	if e!=nil { panic(e) }
	Server.AddHostKey(s)
	
	flag.Parse()
	switch *server{
	case 1:  server1()
	case 2:  server2()
	case 3:  server3()
	case 4:  server4()
	case 5:  server5()
	case 11:
		Client.Addr = "127.0.0.1:8001"
		sshproxy.Add(&Client)
		log.Println(sshproxy.Resolve("de.wikipedia.org"))
	
	case 10:  server10()
	default: flag.PrintDefaults()
	}
	
}
