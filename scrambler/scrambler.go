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

/*
 Multi-Hop Anonymization Protocol for one connection. This Protocol uses
 the public key function Curve25519 and the cipher Twofish in Counter Mode.
 A Session consists of two end points (Client and Server) and zero or more
 Intermediate stations. The Intermediate station scrambles the key-exchange
 handshake without braking it and it scrambles the communicated data without
 breaking it. The Intermediate station's input and output can not be associated
 with each other (to identify a Session), except with a 256-bit brute force attack.
*/
package scrambler

import "io"
import "encoding/binary"
import "golang.org/x/crypto/curve25519"
//import "git.schwanenlied.me/yawning/chacha20.git"

/*
 * Initially, this was "git.schwanenlied.me/yawning/chacha20.git" but is mirrored
 * in order to assure availability under all circumstances.
 */
import "github.com/mad-day/chacha20"

import "crypto/rand"
import "crypto/cipher"
import "fmt"

const (
	ivC2S = "Client-to-Server"
	ivS2C = "Server-to-Client"
	ivP2P = "Peer---to---Peer"
)

func hex(i interface{}) string{
	return fmt.Sprintf("%X",i)
}

type CryptoRecord struct{
	Array [3][32]byte
}

type wrapper struct{
	C io.Closer
	cipher.StreamReader
	cipher.StreamWriter
}
func (w *wrapper) Close() error{
	if w.C==nil { return nil }
	return w.C.Close()
}

func encryptIV(key, ivi, ivo []byte){
	var out [32]byte
	var nonce [chacha20.HNonceSize]byte
	copy(nonce[:],ivi)
	chacha20.HChaCha(key,&nonce,&out)
	copy(ivo,out[:])
}

func mustChaCha(c *chacha20.Cipher,e error) *chacha20.Cipher {
	if e!=nil { panic(e) }
	return c
}

/* Client side function to start a session. */
func Initiator(srv io.ReadWriteCloser) (io.ReadWriteCloser,error){
	var t [3][32]byte
	var r CryptoRecord
	
	for i := range t {
		rand.Read(t[i][:])
		curve25519.ScalarBaseMult(&(r.Array[i]),&(t[i]))
	}
	
	e := binary.Write(srv,binary.BigEndian,r)
	if e!=nil { return nil,e }
	e = binary.Read(srv,binary.BigEndian,&r)
	if e!=nil { return nil,e }
	
	for i := range t {
		curve25519.ScalarMult(&(r.Array[i]),&(t[i]),&(r.Array[i]))
	}
	
	//------------------------------------------------------------
	
	iv := []byte(ivC2S)
	eiv := make([]byte,24)
	c2s := make(multiStream,3)
	for i := range r.Array {
		encryptIV(r.Array[i][:],iv,eiv)
		c2s[i] = mustChaCha(chacha20.NewCipher(r.Array[i][:],eiv))
	}
	
	iv = []byte(ivS2C)
	s2c := make(multiStream,3)
	for i := range r.Array {
		encryptIV(r.Array[i][:],iv,eiv)
		s2c[i] = mustChaCha(chacha20.NewCipher(r.Array[i][:],eiv))
	}
	
	return &wrapper{
		srv,
		cipher.StreamReader{s2c,srv},
		cipher.StreamWriter{c2s,srv,nil},
	},nil
}

/*
Intermediate station function to start a session.
If an error is returned, please close the connections, otherwise, don't.
*/
func Intermediate(clt io.ReadWriteCloser,srv io.ReadWriteCloser) error{
	const (
		SALT = iota
		SALT2
		CLTK
		SRVK
		N_Ts /* Number of t-Keys */
	)
	
	var t [N_Ts][32]byte
	var K [2][32]byte
	var r CryptoRecord
	
	for i := range t {
		rand.Read(t[i][:])
	}
	
	//-------------------------------------------------------
	
	/*  [A,B,X] -> [B,C,X]  */
	
	e := binary.Read(clt,binary.BigEndian,&r)
	if e!=nil { return e }
	
	curve25519.ScalarMult(&(K[0]),&(t[CLTK]),&(r.Array[0]))
	r.Array[0] = r.Array[1]
	curve25519.ScalarBaseMult(&(r.Array[1]),&(t[SRVK]))
	
	/* Scramble B and X */
	
	curve25519.ScalarMult(&(r.Array[0]),&(t[SALT]),&(r.Array[0]))
	curve25519.ScalarMult(&(r.Array[2]),&(t[SALT2]),&(r.Array[2]))
	
	e = binary.Write(srv,binary.BigEndian,r)
	if e!=nil { return e }
	
	//-------------------------------------------------------
	
	/*  [B,C,X] -> [A,B,X]  */
	
	e = binary.Read(srv,binary.BigEndian,&r)
	if e!=nil { return e }
	
	curve25519.ScalarMult(&(K[1]),&(t[SRVK]),&(r.Array[1]))
	r.Array[1] = r.Array[0]
	curve25519.ScalarBaseMult(&(r.Array[0]),&(t[CLTK]))
	
	/* Scramble B and X */
	
	curve25519.ScalarMult(&(r.Array[1]),&(t[SALT]),&(r.Array[1]))
	curve25519.ScalarMult(&(r.Array[2]),&(t[SALT2]),&(r.Array[2]))
	
	e = binary.Write(clt,binary.BigEndian,r)
	if e!=nil { return e }
	
	
	
	//-------------------------------------------------------
	
	/* Apply Transcryption (A and C) */
	
	iv := []byte(ivC2S)
	eiv := make([]byte,24)
	c2s := make(multiStream,2)
	for i := range K {
		encryptIV(K[i][:],iv,eiv)
		c2s[i] = mustChaCha(chacha20.NewCipher(K[i][:],eiv))
	}
	
	s2c := make(multiStream,2)
	iv = []byte(ivS2C)
	for i := range K {
		encryptIV(K[i][:],iv,eiv)
		s2c[i] = mustChaCha(chacha20.NewCipher(K[i][:],eiv))
	}
	
	eclt := cipher.StreamReader{c2s,clt}
	esrv := cipher.StreamReader{s2c,srv}
	
	go dispatch(eclt,srv)
	go dispatch(esrv,clt)
	return nil
}

/* Server side function to start a session. */
func Endpt(clt io.ReadWriteCloser) (io.ReadWriteCloser,error) {
	var t [3][32]byte
	var r,r2 CryptoRecord
	e := binary.Read(clt,binary.BigEndian,&r)
	if e!=nil { return nil,e }
	
	for i := range t {
		rand.Read(t[i][:])
		curve25519.ScalarBaseMult(&(r2.Array[i]),&(t[i]))
		curve25519.ScalarMult(&(r.Array[i]),&(t[i]),&(r.Array[i]))
	}
	
	e = binary.Write(clt,binary.BigEndian,r2)
	if e!=nil { return nil,e }
	
	
	//-------------------------------------------------------
	
	iv := []byte(ivC2S)
	eiv := make([]byte,24)
	c2s := make(multiStream,3)
	for i := range r.Array {
		encryptIV(r.Array[i][:],iv,eiv)
		c2s[i] = mustChaCha(chacha20.NewCipher(r.Array[i][:],eiv))
	}
	
	iv = []byte(ivS2C)
	s2c := make(multiStream,3)
	for i := range r.Array {
		encryptIV(r.Array[i][:],iv,eiv)
		s2c[i] = mustChaCha(chacha20.NewCipher(r.Array[i][:],eiv))
	}
	
	return &wrapper{
		clt,
		cipher.StreamReader{c2s,clt},
		cipher.StreamWriter{s2c,clt,nil},
	},nil
}

