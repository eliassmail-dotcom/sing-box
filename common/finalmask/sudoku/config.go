package sudoku

import (
	"fmt"
	"net"
)

// Config is the Xray v26.11.9 Sudoku settings subset. Legacy snake_case
// aliases are accepted with Xray's fallback semantics.
type Config struct {
	Password string `json:"password"`
	Ascii string `json:"ascii"`
	CustomTable string `json:"customTable"`
	CustomTables []string `json:"customTables"`
	PaddingMin uint32 `json:"paddingMin"`
	PaddingMax uint32 `json:"paddingMax"`
	LegacyCustomTable string `json:"custom_table"`
	LegacyCustomTables []string `json:"custom_tables"`
	LegacyPaddingMin uint32 `json:"padding_min"`
	LegacyPaddingMax uint32 `json:"padding_max"`
}

func(c *Config)GetPassword()string{return c.Password}
func(c *Config)GetAscii()string{return c.Ascii}
func(c *Config)GetCustomTable()string{if c.CustomTable!=""{return c.CustomTable};return c.LegacyCustomTable}
func(c *Config)GetCustomTables()[]string{if len(c.CustomTables)>0{return c.CustomTables};return c.LegacyCustomTables}
func(c *Config)GetPaddingMin()uint32{if c.PaddingMin!=0{return c.PaddingMin};return c.LegacyPaddingMin}
func(c *Config)GetPaddingMax()uint32{if c.PaddingMax!=0{return c.PaddingMax};return c.LegacyPaddingMax}

// Mask is immutable. Tables are compiled once per outbound, and the large
// group index is shared globally without retaining passwords in a cache.
type Mask struct{
	tables []*table
	pMin,pMax int
}
func New(c *Config)(*Mask,error){
	if c==nil{return nil,fmt.Errorf("nil sudoku settings")}
	if len(c.Password)>1024||len(c.CustomTables)>8||len(c.LegacyCustomTables)>8{return nil,fmt.Errorf("sudoku config budget exceeded")}
	if c.GetPaddingMin()>100||c.GetPaddingMax()>100{return nil,fmt.Errorf("sudoku padding must be 0-100")}
	tables,err:=getTables(c)
	if err!=nil{return nil,err}
	pMin,pMax:=normalizedPadding(c)
	return &Mask{tables:tables,pMin:pMin,pMax:pMax},nil
}

// WrapClient uses Xray's classic uplink and packed downlink.
func(m *Mask)WrapClient(c net.Conn)net.Conn{return m.wrap(c,true)}
// WrapServer is used by codec interoperability tests, not by LX inbounds.
func(m *Mask)WrapServer(c net.Conn)net.Conn{return m.wrap(c,false)}

func(m *Mask)wrap(c net.Conn,client bool)net.Conn{
	if client{
		encoder:=newCodec(m.tables,m.pMin,m.pMax)
		decoder:=&packedStreamDecoder{layouts:tablesToLayouts(m.tables)}
		return newConn(c,encoder.encode,decoder)
	}
	encoder:=newPackedEncoder(m.tables,m.pMin,m.pMax)
	decoder:=&hintDecoder{tables:m.tables}
	return newConn(c,encoder.encode,decoder)
}
