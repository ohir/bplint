

> bplint
Command bplint is an accompanying tool for the [Bitpeek package](https://github.com/ohir/bitpeek).

Bplint looks through given go source files for occurrence of tagged Bitpeek
format strings then it checks every found one for common pitfalls.
Bplint also prints on the console clear mapping from the string to input's bits:


	$ bplint -m ampl bplint_test.go
	
	--- Pic: "Example" in bplint_test.go line 22 ------------------------
	OK.
	bits:|63 3b 61|    60|   59|58 11b 48|47..     32b     ..16|15 16b 0|
	             ^      ^     ^         ^                     ^        ^|
	cmds:¨¨Type:'F¨ 'EXT=¨.ACK=¨ Id:0xFHH¨ from IPv4.Address32@¨¨¨:D.16@¨

Format string description is to be found at [GoDoc.org](https://godoc.org/github.com/ohir/bitpeek)

### Usage
This is a CLI tool intended for UTF-8 capable terminals. If you can not
afford one you need to tinker with sources and change all non ascii
prints yourself ;).


	bplint [-q][-m MSTR] file.go [...]
	
	  Options:
	 -q      : Supress terminal output. Exits with 1 on any error.
	 -m MSTR : Check only picstrings with a tag that contains MSTR.
	                  Looks into //bitpeek[:Name[:skip]] comments.

### Marking picstrings
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

### Valid Numbers
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




- - -
Generated by [godoc2md](http://godoc.org/github.com/davecheney/godoc2md)
