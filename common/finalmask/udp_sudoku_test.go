package finalmask

import (
	"encoding/json"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestLXFinalMaskUDPSudokuGuard(t *testing.T){
	o:=option.LXFinalMaskUDPMaskOptions{Type:"sudoku",Settings:json.RawMessage(`{"password":"test","paddingMin":20,"paddingMax":40}`)}
	m,err:=NewUDPChain([]option.LXFinalMaskUDPMaskOptions{o})
	if err!=nil||m==nil{t.Fatalf("valid config %v",err)}
	if _,err:=NewUDPChain([]option.LXFinalMaskUDPMaskOptions{o,udpOpts(`{"password":"test-key"}`)[0]});err==nil{t.Fatal("accepted unvalidated composition")}
	o.Settings=json.RawMessage(`{"paddingMax":101}`)
	if _,err:=NewUDPChain([]option.LXFinalMaskUDPMaskOptions{o});err==nil{t.Fatal("invalid padding accepted")}
}
