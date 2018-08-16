// Copyright 2018 OHIR-RIPE. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package main

import (
	//"fmt"
	//"runtime"
	"testing"
)

// bullets ➊ ➋ ➌ ➍ ➎ ➏ ➐ ➑ ➒ ➓

var lintTests = []struct {
	desc string
	pic  string
	out  [4]string
}{
	// /*
	//bitpeek:Example:1
	{`Bitpeek Example`, `Type:'F 'EXT=.ACK= Id:0xFHH from IPv4.Address32@:D.16@`,
		[4]string{
			`OK.`,
			`bits:|63 3b 61|    60|   59|58 11b 48|47..     32b     ..16|15 16b 0|`,
			`             ^      ^     ^         ^                     ^        ^|`,
			`cmds:¨¨Type:'F¨ 'EXT=¨.ACK=¨ Id:0xFHH¨ from IPv4.Address32@¨¨¨:D.16@¨`},
	},
	{`Empty string`, ``,
		[4]string{
			`OK.`,
			`bits:|`,
			`     |`,
			`cmds:¨`},
	},
	{`No commands`, `PicString`,
		[4]string{
			`OK.`,
			`bits:|`,
			`     |`,
			`cmds:¨PicString`},
	},
	//bitpeek:Ovl:1
	{`Bits overflow`, `ER=TR=BR=CX= BHHHHHHH HHHHHHHH`,
		[4]string{
			`Error: Pic string takes more than 64 bits!`,
			` ERR:| 64| 63| 62| 61|60 29b 32|31.. 32b ..0|`,
			`        ^   ^   ^   ^         ^            ^|`,
			`cmds:¨ER=¨TR=¨BR=¨CX=¨ BHHHHHHH¨¨¨¨ HHHHHHHH¨`},
	},
	{`Bad quoted`, `New Ident:EFHH 'Some Flag 'ER? and a tail`,
		[4]string{
			`OK.`,
			`bits:|3..       3b       ..1|       0|`,
			`                           ^        ^|`,
			`cmds:¨New Ident:EFHH 'Some F¨lag 'ER?¨ and a tail`},
	},
	//bitpeek:Quot:1
	{`Good quoted, bad Hex`, `New Ident:EFHH 'Some Flag''ER? and a tail`,
		[4]string{
			`Error: Bad shape of a Hex number. See section 'Valid Numbers' in docs.`,
			``,
			`New Ident:EFHH 'Some Flag''ER? and a tail `,
			`          ^^^^HERE`},
	},
	//bitpeek:Quot:1
	{`Good quoted, good Hex`, `New Ident:FHH 'Some Flag''ER? and a tail`,
		[4]string{
			`OK.`,
			`bits:|11..  11b ..1|               0|`,
			`                  ^                ^|`,
			`cmds:¨New Ident:FHH¨ 'Some Flag''ER?¨ and a tail`},
	},
	{`Invalid Ddd@ 1`, `D.22@`,
		[4]string{
			`Error: Can't find valid start command for this dd@.`,
			``,
			`D.22@ `,
			` ^^^^HERE`},
	},
	{`Octals`, `Bad one:BEFF (9b)`,
		[4]string{
			`Error: Misleading use of B/E/F number. See section 'Valid Numbers' in docs.`,
			``,
			`Bad one:BEFF (9b) `,
			`        ^^^^HERE`},
	},
	//bitpeek:Octals:1
	{`Octals`, `\Good ones: 0EFF and:EFF`,
		[4]string{
			`OK.`,
			`bits:|15..    8b   ..8|7.. 8b ..0|`,
			`                     ^          ^|`,
			`cmds:¨\Good ones: 0EFF¨¨¨ and:EFF¨`},
	},
	{`OK IP`, `IPv4.Address32@`,
		[4]string{
			`OK.`,
			`bits:|31..   32b  ..0|`,
			`                    ^|`,
			`cmds:¨IPv4.Address32@¨`},
	},
	{`Bad IP`, `IPv4,Address32@`,
		[4]string{
			`Error: Invalid pic for IPv4.`,
			``,
			`IPv4,Address32@ `,
			`^^^^^^^^^^^^^^^HERE`},
	},
	{`Just skip 64`, `!64@`,
		[4]string{
			`OK.`,
			`bits:|63 64b 0|`,
			`             ^|`,
			`cmds:¨¨¨¨¨!64@¨`},
	},
	{`Turn Off octal checks`, `EF*EFFF*`,
		[4]string{
			`OK.`,
			`bits:|15 2b 14|13 3b 11|10 2b 9|8 9b 0|`,
			`             ^        ^       ^      ^|`,
			`cmds:¨¨¨¨¨¨¨¨E¨¨¨¨¨¨¨¨F¨¨¨¨¨¨*E¨¨¨¨FFF¨*`},
	},
	{`LongDec`, `D64................64@`,
		[4]string{
			`OK.`,
			`bits:|63..      64b      ..0|`,
			`                           ^|`,
			`cmds:¨D64................64@¨`},
	},
	{`Bad LongDec`, `D62................62@`,
		[4]string{
			`Error: Can't find valid start command for this dd@.`,
			``,
			`D62................62@ `,
			`                  ^^^^HERE`},
	},
	{`ShortDec`, `D.11@`,
		[4]string{
			`OK.`,
			`bits:|10 11b 0|`,
			`             ^|`,
			`cmds:¨¨¨¨D.11@¨`},
	},
	{`Bad Short Dec`, `D..11@`,
		[4]string{
			`Error: Can't find valid start command for this dd@.`,
			``,
			`D..11@ `,
			`  ^^^^HERE`},
	},
	{`Short Dec17`, `D..17@`,
		[4]string{
			`OK.`,
			`bits:|16 17b 0|`,
			`             ^|`,
			`cmds:¨¨¨D..17@¨`},
	},
	{`Hex shapes`, `BH EH FH BHH EHH FHH BHHH`,
		[4]string{
			`OK.`,
			`bits:|60 5b 56|55 6b 50|49 7b 43|42 9b 34|33 10b 24|23 11b 13|12 13b 0|`,
			`             ^        ^        ^        ^         ^         ^        ^|`,
			`cmds:¨¨¨¨¨¨¨BH¨¨¨¨¨¨ EH¨¨¨¨¨¨ FH¨¨¨¨¨ BHH¨¨¨¨¨¨ EHH¨¨¨¨¨¨ FHH¨¨¨¨ BHHH¨`},
	},
	{`Bad glued B`, `HBBBBBBB`,
		[4]string{
			`Error: Misleading use of B/E/F number. See section 'Valid Numbers' in docs.`,
			``,
			`HBBBBBBB `,
			`^^HERE`},
	},
	{`Separate shorthex`, `F E BBBB E F E E F F H HH HHH`,
		[4]string{
			`OK.`,
			`bits:|47 3b 45|44 2b 43|42|41|40|39|38 2b 37|36 3b 34|33 2b 32|31 2b 30|29 3b 27|26 3b 24|23 4b 20|19 8b 12|11 12b 0|`,
			`             ^        ^  ^  ^  ^  ^        ^        ^        ^        ^        ^        ^        ^        ^        ^|`,
			`cmds:¨¨¨¨¨¨¨¨F¨¨¨¨¨¨¨ E¨ B¨¨B¨¨B¨¨B¨¨¨¨¨¨¨ E¨¨¨¨¨¨¨ F¨¨¨¨¨¨¨ E¨¨¨¨¨¨¨ E¨¨¨¨¨¨¨ F¨¨¨¨¨¨¨ F¨¨¨¨¨¨¨ H¨¨¨¨¨¨ HH¨¨¨¨¨ HHH¨`},
	},
	{`Empty string`, ``,
		[4]string{
			`OK.`,
			`bits:|`,
			`     |`,
			`cmds:¨`},
	},
	//bitpeek:I18n-pl:1
	{`Unicode (narrow)`, `Tśćę:'F 'EXT=.ACK= Ąę:0xFHH żółć IPv4.Address32@:D.16@`,
		[4]string{
			`OK.`,
			`bits:|63 3b 61|    60|   59|58 11b 48|47..     32b     ..16|15 16b 0|`,
			`             ^      ^     ^         ^                     ^        ^|`,
			`cmds:¨¨Tśćę:'F¨ 'EXT=¨.ACK=¨ Ąę:0xFHH¨ żółć IPv4.Address32@¨¨¨:D.16@¨`},
	},
	//bitpeek:I18n-cn:1
	{`Bitpeek 例`, `包类型'F 'EXT=.ACK= 鉴定:0xFHH 从 IPv4.Address32@:D.16@`,
		[4]string{
			`OK.`,
			`bits:|63 3b 61|    60|   59|58.. 11b ..48|47..    32b    ..16|15 16b 0|`,
			`             ^      ^     ^             ^                   ^        ^|`,
			`cmds:¨包类型'F¨ 'EXT=¨.ACK=¨¨¨ 鉴定:0xFHH¨ 从 IPv4.Address32@¨¨¨:D.16@¨`},
	},
	//bitpeek:norm:1
	{`ShortDecNorm`, "D.11@",
		[4]string{
			`OK.`,
			"bits:|10 11b 0|",
			`             ^|`,
			`cmds:¨¨¨¨D.11@¨`},
	},
	//bitpeek:mis:1
	{`Badscapes forced`, "F''F''F",
		[4]string{
			`OK.`,
			`bits:|8 3b 6|5 3b 3|2 3b 0|`,
			`           ^      ^      ^|`,
			`cmds:¨¨¨¨¨¨F¨¨¨¨''F¨¨¨¨''F¨`},
	},
	{`Badscapes`, "FFF*",
		[4]string{
			`OK.`,
			`bits:|8 9b 0|`,
			`           ^|`,
			`cmds:¨¨¨¨FFF¨*`},
	},
	// */
}

func TestLint(t *testing.T) {
	fails := 0
	for _, v := range lintTests {
		r := Lint(v.pic)
		if r[0] != v.out[0] || r[1] != v.out[1] ||
			r[2] != v.out[2] || r[3] != v.out[3] {
			t.Logf("%s is broken!\nexpected:\n|%s|,\n|%s|,\n|%s|,\n|%s|},\ngot:     \n`%s`,\n`%s`,\n`%s`,\n`%s`},\n",

				v.desc, v.out[0], v.out[1], v.out[2], v.out[3], r[0], r[1], r[2], r[3])
			fails++
		}
	}
	if fails != 0 {
		t.Logf("--- %d of %d tests failed! ---", fails, len(lintTests))
		t.Fail()
	}
}
