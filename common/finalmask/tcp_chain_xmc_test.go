package finalmask
import "testing"
func TestLXFinalMaskTCPChainXMC(t *testing.T){
	for _,s:=range []string{`[{"type":"xmc","settings":{"password":"example","profiles":[]}}]`,`[{"type":"xmc","settings":{"password":"example","profiles":[{"username":"Tester","uuid":"00112233-4455-6677-8899-aabbccddeeff","texturesValue":"x","texturesSignature":"y"}],"typo":true}}]`}{
		if _,err:=NewTCPChain(chainOptions(t,s));err==nil{t.Fatal("accepted invalid XMC")}
	}
	if _,err:=NewTCPChain(chainOptions(t,`[{"type":"xmc","settings":{"password":"example","profiles":[{"username":"Tester","uuid":"00112233-4455-6677-8899-aabbccddeeff","texturesValue":"x","texturesSignature":"y"}]}}]`));err!=nil{t.Fatal(err)}
}
