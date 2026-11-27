package xmc

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strings"
)

type Profile struct {
	Username string
	Uuid []byte
	TexturesValue string
	TexturesSignature string
}
type ProfileOptions struct {
	Username string `json:"username"`
	UUID string `json:"uuid"`
	TexturesValue string `json:"texturesValue"`
	TexturesSignature string `json:"texturesSignature"`
}
type Config struct {
	Hostname string `json:"hostname"`
	Password string `json:"password"`
	Profiles []ProfileOptions `json:"profiles"`
}
type Mask struct {
	profiles []loginProfile
	password, hostname string
	publicKey []byte
}
var usernamePattern=regexp.MustCompile("^[A-Za-z0-9_]{3,16}$")
func parseUUID(s string)([]byte,error){
	if len(s)==36 {
		if s[8]!='-'||s[13]!='-'||s[18]!='-'||s[23]!='-'{return nil,fmt.Errorf("invalid profile UUID")}
		s=strings.ReplaceAll(s,"-","")
	}
	if len(s)!=32{return nil,fmt.Errorf("invalid profile UUID")}
	return hex.DecodeString(s)
}
func New(c *Config)(*Mask,error){
	if c==nil||len(c.Password)==0||len(c.Password)>100{return nil,fmt.Errorf("XMC password must contain 1-100 bytes")}
	if len(c.Hostname)>255||len(c.Profiles)==0||len(c.Profiles)>8{return nil,fmt.Errorf("invalid XMC hostname or profile count")}
	var profiles []*Profile
	for _,p:=range c.Profiles{
		if !usernamePattern.MatchString(p.Username)||len(p.TexturesValue)==0||len(p.TexturesSignature)==0||len(p.TexturesValue)>4096||len(p.TexturesSignature)>4096{return nil,fmt.Errorf("invalid XMC profile")}
		uuid,err:=parseUUID(p.UUID);if err!=nil{return nil,err}
		profiles=append(profiles,&Profile{Username:p.Username,Uuid:uuid,TexturesValue:p.TexturesValue,TexturesSignature:p.TexturesSignature})
	}
	parsed,err:=profilesFromConfig(profiles);if err!=nil{return nil,err}
	private,err:=DeriveRSAKey(c.Password);if err!=nil{return nil,err}
	public,err:=x509.MarshalPKIXPublicKey(&private.PublicKey);if err!=nil{return nil,err}
	return &Mask{profiles:parsed,password:c.Password,hostname:c.Hostname,publicKey:public},nil
}
func(m *Mask) WrapClient(c net.Conn)(net.Conn,error){
	return newClientConn(c,m.profiles,m.password,m.publicKey,m.hostname)
}
