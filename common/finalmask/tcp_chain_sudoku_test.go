package finalmask

import (
	"testing"
)
func TestLXFinalMaskTCPChainSudoku(t *testing.T){
	for _,s:=range []string{
		`[{"type":"sudoku","settings":{"password":"test","ascii":"prefer_ascii"}}]`,
		`[{"type":"fragment","settings":{"length":8}},{"type":"header-custom","settings":{}},{"type":"sudoku","settings":{"password":"test"}}]`,
	}{
		if c,err:=NewTCPChain(chainOptions(t,s));c==nil||err!=nil{t.Fatalf("valid chain %v",err)}
	}
	for _,s:=range []string{
		`[{"type":"sudoku","settings":{"paddingMax":101}}]`,
		`[{"type":"sudoku","settings":{"unknown":1}}]`,
		`[{"type":"sudoku","settings":{}},{"type":"sudoku","settings":{}}]`,
	}{
		if _,err:=NewTCPChain(chainOptions(t,s));err==nil{t.Fatalf("accepted %s",s)}
	}
}
