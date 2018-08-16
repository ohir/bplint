// Copyright 2018 OHIR-RIPE. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

/*
Command bplint is an accompanying tool for the Bitpeek (https://github.com/ohir/bitpeek).

Bplint looks through given go source files for occurrence of tagged Bitpeek
format strings then it checks every found one for common pitfalls.
Bplint also prints on the console clear mapping from the string to input's bits:

   $ bplint -m ampl bplint_test.go

   --- Pic: "Example" in bplint_test.go line 22 ------------------------
   OK.
   bits:|63 3b 61|    60|   59|58 11b 48|47..     32b     ..16|15 16b 0|
                ^      ^     ^         ^                     ^        ^|
   cmds:¨¨Type:'F¨ 'EXT=¨.ACK=¨ Id:0xFHH¨ from IPv4.Address32@¨¨¨:D.16@¨

Format string description is to be found at https://godoc.org/github.com/ohir/bitpeek.



Usage

This is a CLI tool intended for UTF-8 capable terminals. If you can not
afford one you need to tinker with sources and change all non ascii
prints yourself ;).

  bplint [-q][-m MSTR] file.go [...]

    Options:
   -q      : Supress terminal output. Exits with 1 on any error.
   -m MSTR : Check only picstrings with a tag that contains MSTR.
                    Looks into //bitpeek[:Name[:skip]] comments.


Marking picstrings

Bitpeek format string in your source needs to be marked with
special comment line put above the picstring itself:

    //bitpeek:tag:skip

Optional ":tag" field is used to match with linter's -m option.
Picstring tags need not to be unique.

Optional ":skip" number tells linter to skip a few (up to 7) next strings.
It helps where the picstring in the source is a part of a longer literal:

		//bitpeek:sometag:1
		{`Example`, `Type:'F 'EXT=.ACK= Id:0xFHH from IPv4.Address32@:D.16@`},

		// :1 skips string `Example`


Valid Numbers

Bplint does NOT allow for misformated picture of hex or octal numbers.

Hexadecimal number picture MUST start with a single B, E or F (or H)
and then it is all Hs. Linter looks for it because of not uncommon
misunderstanding along "the need for keeping hexadecimal numbers
to byte/halfbyte boundary" that is not true. We and CPUs take bits
from anywhere and show them as a number. Coincidentally in base-16
notation.

Valid hex examples:

  B takes 1 bit, E takes 2b, F takes 3b, H takes 4 bits.

  BH - 5 bit hex    BHH -  9b    BHHH - 13b    BHHHH - 17b ...
  EH - 6 bit hex    EHH - 10b    EHHH - 14b    EHHHH - 18b ...
  FH - 7 bit hex    FHH - 11b    FHHH - 15b    FHHHH - 19b ...
  HH - 8 bit hex


Valid format for octal is a full EFF (2+3+3 bits) prepended with either
digit '0' or a colon. Bplint does not accept eg. 'EEEE' or 'EBEF' constructs
as these are almost certainly mistakes or misunderstandings. Eg. `FFF` is
a 3 times 3 bits not a number that future you or someone else might
interpret as decimal. Put spaces or punctuations inbetween and linter
will allow it:

  `Nine bits to three digits 0-7: F F F`

If you do really want to glue three or more 3bit digits (eg.
to show unix permissions) you can force it using either empty
escapes or an asterisk:

  `Nine bits to three digits 0-7: F''F''F''` or `With asterisk: FFF*`

Now both linter and humans will know you knew what you're doing.
Lint off* or '' trick work with H mixes too.
*/
package main

import (
	"errors"
	"fmt"
	rwid "github.com/mattn/go-runewidth"
	"os"
	"strings"
	ts "text/scanner"
)

// globals, its a cli tool
var files, seen, errcnt int
var match string
var quiet bool

func main() {
	if len(os.Args) == 1 {
		usage()
	}
	fwd := true
	for i, v := range os.Args { // 'flag' is such a mess ;)
		switch {
		case fwd:
			fwd = false
			continue
		case v == `-q`:
			quiet = true
		case v == `-m` && i < len(os.Args)-1:
			match = os.Args[i+1]
			fwd = true
		case v == `-h`:
			usage()
		default:
			lintFile(os.Args[i])
		}
	}
	if quiet && (errcnt > 0 || seen == 0 || files == 0) {
		os.Exit(1)
	}
	if files == 0 {
		prErr(`Error: no files given and/or no files checked!`, quiet)
		usage()
	}
	if seen == 0 {
		prErr(`Error: no matching picstrings found!`, quiet)
	}
	return
}
func lintFile(fn string) {
	fh, err := os.Open(fn)
	if err != nil {
		prErr(fmt.Sprintf("Can not %s", err), quiet)
		errcnt++
		return
	}
	defer fh.Close()
	files++
	var f ts.Scanner
	f.Init(fh)
	f.Filename = fn
	f.Mode = ts.ScanRawStrings | ts.ScanStrings | ts.ScanComments
	skip := -1 // raw strings below to skip
	picname := `unnamed`
	for x := f.Scan(); x != ts.EOF; x = f.Scan() {
		switch {
		case x == ts.Comment: // bitpeek:name:pos
			t := strings.Split(f.TokenText(), ":") // valid: //bitpeek:name:skip
			if t[0] != `//bitpeek` {               // [0] is at least ':'
				continue
			}
			if len(match) > 0 && len(t) > 1 &&
				strings.Index(t[1], match) < 0 {
				continue
			}
			if len(t) > 2 && len(t[1]) > 0 {
				picname = t[1]
			}
			if len(t) > 2 && t[2][0]|7 == 0x37 { // max skip: 7
				skip = int(t[2][0] - 48)
			} else {
				skip = 0
			}
		case skip < 0: // not ours at all
		case x == ts.String && skip > 0:
			skip--
		case x == ts.RawString && skip > 0:
			skip--
		case x == ts.RawString || x == ts.String:
			l := 0
			s := f.TokenText()
			r := Lint(s[1 : len(s)-1])
			if r[0] != `OK.` {
				errcnt++
			}
			seen++
			skip = -1
			if quiet {
				continue
			}
			p := f.Pos()
			d := fmt.Sprintf("--- Pic: \"%s\" in %s line %d -",
				picname, p.Filename, p.Line)
			for _, v := range r {
				ll := rwid.StringWidth(v)
				if l < ll {
					l = ll
				}
			}
			if len(d) < l {
				l = l - len(d)
			} else {
				l = 2
			}
			fmt.Printf("%s%s\n%s\n%s\n%s\n%s\n\n",
				d, lFill('-', l),
				r[0], r[1], r[2], r[3])
			picname = `unnamed`
		}
	}
	return
}
func Lint(pic string) (o [4]string) {
	var e0 strings.Builder // error, if any
	var o1 strings.Builder // |  b28..b27 | b26..  4b ..b24 | b23 | b22..b20 |
	var o2 strings.Builder //           ^                 ^     ^          ^
	var o3 strings.Builder //        Ac:E           Press:H  'CS= ````Stat:F

	rp, err := ckPicStr(pic)
	if err != nil {
		fmt.Fprintf(&e0, "Error: %s", err)
	} else {
		fmt.Fprintf(&e0, "OK.")
	}
	for _, r := range rp {
		fmt.Fprintf(&o1, "%s", r.bits)
		fmt.Fprintf(&o2, "%s", r.mark)
		fmt.Fprintf(&o3, "%s", r.pics)
	}
	o[0] = e0.String()
	o[1] = o1.String()
	o[2] = o2.String()
	o[3] = o3.String()
	return
}

type part struct {
	bits string
	mark string
	pics string
}

func ckPicStr(inp string) (rp []part, err error) {
	pic := "?" + inp + " " // simplify for loop output
	pi := len(pic) - 1     // pic index
	var bi uint16          // bit index, not more than 64
	var quoted, label bool // flow control
	rp = make([]part, 256) // be generous

	ri := len(rp) - 1 // output (part) index
	rp[ri].bits = `|` // close output
	rp[ri].mark = `|`
	ri--

	curbitstart := bi   // ...from bit
	curpicend := pi - 1 // ...picture end
	prevcmd := 'T'      // picstring tail
	for pi > 0 && ri >= 0 {
		pi--
		w := pic[pi]
		switch {
		case pi == 0:
			w = '?'
		case pi > 0 && pic[pi-1] == '\\':
			pi--
			continue
		case w == '\'' && (label || quoted):
			label = false
			quoted = false
			continue
		case w == '\'':
			quoted = true
			continue
		case quoted && w != '\'':
			continue
		case label && w|3 != 63:
			continue
		case w|3 == 63:
			label = true
		case w == 'D' || w < 0x3c || w > 0x48:
			continue
		}
		if prevcmd == 'T' { // output the tail
			rp[ri].pics = fmt.Sprintf("%s", pic[pi+1:curpicend+1])
			ri--
		} else { // output previous part
			var b strings.Builder // |  b28..b27 | b26..  4b ..b24 | b23 | b22..b20 |
			var m strings.Builder //           ^                 ^     ^          ^
			var s strings.Builder //        Ac:E           Press:H  'CS= ````Stat:F

			lenB := bi - curbitstart // field bitlength
			lenC := rwid.StringWidth(pic[pi:curpicend])
			lenC += 1 // add for separator

			// bitdesc
			var bDesc string
			if lenB == 1 {
				b.Reset()
				fmt.Fprintf(&b, "|%d", curbitstart) // single bit
				bDesc = b.String()
				if lenC > len(bDesc) { // adjust
					adj := lenC - len(bDesc)
					b.Reset()
					fmt.Fprintf(&b, "|")
					for i := adj; i > 0; i-- {
						//b.WriteByte('.') // adjust left
						b.WriteByte(' ') // adjust left
					}
					fmt.Fprintf(&b, "%d", curbitstart)
					bDesc = b.String()
				}
			}
			if lenB > 1 { // output previous part
				b.Reset()
				fmt.Fprintf(&b, "|%d %db %d", bi-1, lenB, curbitstart)
				bdMid := b.String()
				b.Reset()
				fmt.Fprintf(&b, "|%d.. %db ..%d", bi-1, lenB, curbitstart)
				bdLong := b.String()
				b.Reset()
				switch {
				default:
					panic("May not happen!")
				case lenC <= len(bdMid): // short
					bDesc = bdMid
				case lenC <= len(bdLong): // long
					bDesc = bdLong
				case lenC > len(bdLong): // adjust desc to fit pic
					adj := lenC - len(bdLong)
					b.Reset()
					fmt.Fprintf(&b, "|%d.. ", bi-1)
					for i := adj - adj/2; i > 0; i-- {
						//b.WriteByte('<') // adjust left
						b.WriteByte(' ') // adjust left
					}
					fmt.Fprintf(&b, "%db", lenB)
					for i := adj / 2; i > 0; i-- {
						//b.WriteByte('>') // adjust right
						b.WriteByte(' ') // adjust right
					}
					fmt.Fprintf(&b, " ..%d", curbitstart)
					bDesc = b.String()
				}
			}
			s.Reset()
			if lenC > 0 {
				for i := lenC; i < len(bDesc); i++ {
					s.WriteRune('¨') // mark our inserts with diaresis
				}
				fmt.Fprintf(&s, "%s¨", pic[pi+1:curpicend+1])
			}
			if lenB > 0 { // make marker
				m.Reset()
				m.WriteByte(' ')
				for i := len(bDesc) - 2; i > 0; i-- {
					m.WriteByte(' ')
				}
				m.WriteByte('^')
			}
			rp[ri].bits = bDesc
			rp[ri].mark = m.String()
			rp[ri].pics = s.String()
			ri--
		} // output previous part
		if pi <= 0 {
			break
		}

		curpicend = pi
		curbitstart = bi
		switch {
		case w|3 == 63 || w == 'B': // single bits - bbChain
			prevcmd = 'L'
			bi++
			if pi > 0 && w == 'B' { // check for glued A..H
				nn := pic[pi-1]
				if nn != 'B' && !(nn < 49 || nn|1 == 0x3b || nn > 72) {
					err = errors.New(
						"Misleading use of B/E/F number. See section 'Valid Numbers' in docs.")
					break
				}
			}
		case w == '@': // varbits, Number
			prevcmd = 'N'
			pi, bi, err = ckVarblen(pic, pi, bi)
		default: // ACEFGH - bbRange
			prevcmd = 'N' // number
			pi, bi, err = ckRanges(pic, pi, bi)
		}
		if err != nil {
			var sp strings.Builder
			for i := range pic[:curpicend] {
				if i >= pi-2 { // -2: show at least boundary
					sp.WriteByte('^')
				} else {
					sp.WriteByte(' ')
				}
			}
			ri = len(rp) - 1
			rp[ri].bits = ``
			rp[ri].pics = sp.String() + `HERE`
			rp[ri].mark = pic[1:]
			return rp[ri:], err
		}
	}
	rp[ri].bits = `bits:`
	rp[ri].mark = `     `
	rp[ri].pics = `cmds:¨`
	if bi > 64 {
		rp[ri].bits = ` ERR:`
		err = errors.New(
			"Pic string takes more than 64 bits!")
	}
	return rp[ri:], err
}

func ckVarblen(pic string, pi int, bi uint16) (int, uint16, error) {
	if pi < 3 { // !dd@
		return 0, bi, errors.New("Misplaced @")
	}
	k := (10 * uint8(pic[pi-2]-48)) + uint8(pic[pi-1]-48)
	var d = 4
	if k > 16 {
		d = int(k / 3)
	}
	switch {
	case k == 0, k > 64:
		return pi - 2, bi, errors.New("Bad bitcount.")
	case pi > 2 && pic[pi-3] == '!': // !dd@ skip dd bits
		pi -= 3
		bi += uint16(k)
	case pi > d-1 && pic[pi-d] == 'D': // D.dd@ Decimal
		pi -= d
		bi += uint16(k)
	case pi > 13 && pic[pi-14] == 'I': // I##.###.###.32@ is not now allowed
		pi -= 14
		bi += 32
		if pic[pi:pi+15] != `IPv4.Address32@` { // force it
			return pi, bi, errors.New("Invalid pic for IPv4.")
		}
	default:
		return pi - 2, bi, errors.New("Can't find valid start command for this dd@.")
	}
	return pi, bi, nil
}

//
// Valid Numbers
//
// before series of H can come a *single* completing digit of F, E or B (giving valid hex number)
// before series of F can come a *single* completing digit of E or B (giving valid octal number)
// any consecutive mix of EFH is not allowed unless escaped with a '*' marker after the offending
// sequence of commands. See _test file.
// chain of Bs is allowed
func ckRanges(pic string, pi int, bi uint16) (int, uint16, error) {
	var c byte
	w := pic[pi]
	if pi > 0 {
		c = pic[pi-1]
	}
	switch w {
	case 'H': // HHH FHH EHH BHH
	nextH:
		bi += 4
		if pi > 0 && pic[pi-1] == 'H' {
			pi--
			goto nextH
		}
		if pi > 0 { // only single B|E|F allowed after H's
			c = pic[pi-1]
			switch c {
			case 'F':
				bi += 3
			case 'E':
				bi += 2
			case 'B':
				bi += 1
			default:
				pi++ // no match - negate -- below
			}
			pi--
		}
		if pi > 0 { // check for wrongs, no hex continuation can be glued after FEB
			c = pic[pi-1]
			if c == 'H' ||
				c == 'F' ||
				c == 'E' ||
				c == 'B' {
				return pi, bi, errors.New(
					"Bad shape of a Hex number. See section 'Valid Numbers' in docs.")
				// Eg. BHH 9b, EHH 10b, FHH 11b, HHH 12b, BHHH 13b and so on.
			}
		}
	case 'C':
		bi += 8
	case 'A':
		bi += 7
	case 'G':
		bi += 5
	case 'F': // FFF EFF BFF
		var off, n, nn byte // for '*' switch, nExt char
		var oct bool
		efs := 1
		if pi < len(pic)-1 {
			off = pic[pi+1]
		}
	nextF:
		bi += 3
		if pi > 0 && pic[pi-1] == 'F' {
			efs++
			pi--
			goto nextF
		}
		if efs == 2 && pi > 0 && pic[pi-1] == 'E' {
			bi += 2
			pi--
			oct = true // valid octal shape
		}
		// checks
		if pi > 0 {
			nn = pic[pi-1]
		}
		switch {
		case off == '*':
			// OK. checks turned off
		case efs == 1 && (n < 65 || n > 72):
			// ok, lone F, no A-F commands in front of
		case oct && (nn < 49 || nn|1 == 0x3b || nn > 72):
			// ok, Octal prepended by chr <= '0', :;, chr >= 'I'
		default:
			return pi, bi, errors.New(
				"Misleading use of B/E/F number. See section 'Valid Numbers' in docs.")
		}
	case 'E': // separate entity
		var off, n byte // for '*' switch, nExt char
		efs := 1
	nextE:
		bi += 2
		if pi > 0 && pic[pi-1] == 'E' {
			efs++
			pi--
			goto nextE
		}
		if pi < len(pic)-1 {
			off = pic[pi+1]
		}
		if pi > 0 {
			n = pic[pi-1]
		}
		switch {
		case off == '*':
			// OK. checks turned off
		case efs == 1 && pi == 0:
			// ok, allow for opening single E
		case efs == 1 && (n < 65 || n > 72):
			// ok, no direct command ahead
		default:
			return pi, bi, errors.New(
				"Misleading use of B/E/F number. See section 'Valid Numbers' in docs.")
		}
	default:
	}
	return pi, bi, nil
}
func usage() {
	fmt.Printf("%s\nUsage: %s [options] file [file...]\n"+
		"\n    Options:\n\n"+
		"   -q      : Suppress terminal output.  Exit with 1 on any error.\n"+
		"   -m MSTR : Check only picstrings with a tag that contains MSTR.\n"+
		"                      Looks into //bitpeek[:tag[:skip]] comments.\n\n",
		lFill('_', len(fmt.Sprintf("Usage: %s [options] file [file...]", os.Args[0]))),
		os.Args[0])
	os.Exit(0)
}
func prErr(s string, q bool) {
	if !q {
		fmt.Fprintf(os.Stderr, "%s\n%s\n", lFill('_', len(s)), s)
	}
}
func lFill(c byte, n int) (r []byte) {
	r = make([]byte, n)
	for i := range r {
		r[i] = c
	}
	return
}
