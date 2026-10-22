#!/usr/bin/env bash
# Portability gate for the zig-built cogbox tools: fail when the machine code
# uses an instruction from an extension the pinned CPU level does not include.
# It is a denylist over objdump output (the classes below), not a decoder.
# usage: check_tools_isa.sh <x86_64_v2_avx|x86_64_v3> <bin/cogbox> [<other ELF>...]
# The first ELF must also keep zig std's hardware AES and carry-less multiply
# paths (aesenc, pclmul): a level without them falls back to table AES.
set -euo pipefail
[ $# -ge 2 ] || { echo "usage: $0 <x86_64_v2_avx|x86_64_v3> <ELF>..." >&2; exit 2; }
level=$1; shift
# Beyond x86-64-v3 (+aes +pclmul): AVX-512 (zmm, EVEX-only registers, mask
# registers, k* ops, BCST/{sae}/{z}/{evex} markers, EVEX-only mnemonics on
# xmm/ymm, AVX512-FP16), SHA/SHA512/SM3/SM4, AMD-only SSE4a/XOP/TBM/LWP and
# friends, wide VAES/VPCLMULQDQ, GFNI, VNNI and the newer VEX extensions, AMX,
# ADX, RDRAND/RDSEED, FSGSBASE, TSX, post-Haswell system instructions (up to
# UINTR and TSXLDTRK), and opcodes objdump cannot decode. F16C's vcvtph2ps and
# vcvtps2ph stay v3; every other vcvt to or from ph/sh is FP16.
# An operand-less mnemonic ends the line, hence (\s|$).
beyond_v3='zmm[0-9]|[xy]mm(1[6-9]|2[0-9]|3[01])|[ ,{]k[0-7]([ ,}]|$)|\sk(mov|and|or|xor|xnor|not|shift|unpck|test|add)[a-z]*\s|sha1(rnds4|nexte|msg[12])|sha256(rnds2|msg[12])|\s(extrq|insertq|movntss|movntsd)(\s|$)|\s(vpcmov|vpperm|vfrcz(p[sd]|s[sd])|vpmacs[a-z]*|vpmadcs[a-z]*|vprot[bwdq]|vpsha[bwdq]|vpshl[bwdq]|vpcom[a-z]*|vph(add|sub)u?(b[wdq]|w[dq]|dq)|vpermil2p[sd])(\s|$)|\s(blcfill|blci|blcic|blcmsk|blcs|blsfill|blsic|t1mskc|tzmsk)(\s|$)|\s(clzero|mwaitx|monitorx|rdpru|llwpcb|slwpcb|lwpins|lwpval)(\s|$)|vaes(enc|dec)(last)?\s+[yz]mm|vpclmul[a-z]*dq\s+[yz]mm|gf2p8|\svpdp(bu|ws)sds?\s|\s(ldtilecfg|sttilecfg|tileloadd|tileloaddt1|tilestored|tilezero|tdpb[a-z]*)(\s|$)|\s(clflushopt|clwb|xsavec|xsaves|xrstors|rdpid|rdpkru|wrpkru|movdiri|movdir64b|serialize|enqcmd|enqcmds|wbnoinvd|ptwrite|umonitor|umwait|tpause|cldemote|hreset|senduipi|clui|stui|testui|uiret|xsusldtrk|xresldtrk)(\s|$)|BCST|\{(rn-|rd-|ru-|rz-)?sae\}|\{z\}|\{evex\}|\sv(pternlog[dq]|p(and|andn|or|xor)[dq]|perm[it]2([bwdq]|p[sd])|perm[bw]|pmovu?s?(q[bwd]|d[bw]|wb)|pmov[bwdq]2m|pmovm2[bwdq]|align[dq]|pro[lr]v?[dq]|pconflict[dq]|plzcnt[dq]|popcnt[bwdq]|pcompress[bwdq]|pexpand[bwdq]|ps[lr]lvw|psravw|psravq|psraq|pmullq|pmax[su]q|pmin[su]q|pabsq|pshldv?[wdq]|pshrdv?[wdq]|movw|movdq[au](8|16|32|64)|blendmp[sd]|pblendm[bwdq]|shuf[if](32x4|64x2)|(insert|extract)[if](32x4|64x2|32x8|64x4)|broadcast[if](32x2|32x4|64x2|32x8|64x4)|getexp[ps][sd]|getmant[ps][sd]|scalef[ps][sd]|fixupimm[ps][sd]|rndscale[ps][sd]|rcp14[ps][sd]|rsqrt14[ps][sd]|range[ps][sd]|reduce[ps][sd]|fpclass[ps][sd]|cvtt?[ps][sd]2u[a-z]*|cvtu[a-z0-9]*|cvtt?p[sd]2qq|cvtqq2p[sd]|dbpsadbw|pmultishiftqb|ptestn?m[bwdq]|pbroadcastm[a-z0-9]*|p2intersect[dq]|dpbf16ps|cvtne2ps2bf16|exp2p[sd]|rcp28[ps][sd]|rsqrt28[ps][sd]|(add|sub|mul|div|min|max|sqrt|rcp|rsqrt|getexp|getmant|scalef|reduce|rndscale|fpclass|cmp|u?comi|f(n?m(add|sub)|maddsub|msubadd)[0-9]+|fc?(madd|mul)c)[ps]h|movsh|cvtt?(ph2([dqu][a-z]*|pd|psx|w)|sh2[a-z]+)|cvt[a-z0-9]*2sh|cvt(dq|pd|qq|w)2ph|cvtps2phx)\s|\s(vsha512[a-z0-9]*|vsm3[a-z0-9]*|vsm4[a-z0-9]*|vpdp(b[su][su]|w[su][su])ds?|vpmadd52[lh]uq|vbcstne[a-z0-9]*|vcvtne(ps2bf16|ebf162ps|eph2ps|obf162ps|oph2ps))\s|\s(adcx|adox|rdseed|rdrand|rdfsbase|rdgsbase|wrfsbase|wrgsbase|xbegin|xend|xabort|xtest|tilerelease)(\s|$)|\(bad\)'
# x86-64-v3 additions a v2+avx level must not use: BMI1/2, LZCNT, MOVBE, FMA,
# F16C and AVX2 (including the integer vp* forms on ymm, which AVX1 lacks).
# (tzcnt is deliberately absent: it decodes as bsf on older CPUs and compilers
# emit it as rep bsf on purpose.)
v3_only='\s(shlx|shrx|sarx|rorx|pdep|pext|mulx|andn|bextr|blsi|blsr|blsmsk|bzhi|lzcnt|movbe)\s|\svfn?m(add|sub)[0-9a-z]*\s|\svcvt(ph2ps|ps2ph)\s|\svpbroadcast[bwdq]\s|\svperm(2i128|q|d|pd|ps)\s|\sv(inserti128|extracti128)\s|\svp?gather[a-z]*\s|\svpmaskmov[dq]\s|\svps(ll|rl|ra)v[dq]\s|\svp([abchmosux][a-z0-9]*|g[a-z0-9]*|erm[dq]|ermp[sd])\s+[^#]*ymm|\svpblendd\s|\svbroadcasti128\s|\svbroadcasts[sd]\s+[xy]mm[0-9]+,\s*xmm|\sv(movntdqa|mpsadbw)\s+ymm'
case $level in
	x86_64_v2_avx) pat="$beyond_v3|$v3_only" ;;
	x86_64_v3) pat=$beyond_v3 ;;
	*) echo "unknown level $level" >&2; exit 2 ;;
esac
# grep -c that fails closed: exit 1 (no match) is a count of 0, exit 2 (a bad
# pattern, an unreadable file) aborts instead of passing with an empty count.
count() {
	local c
	c=$(grep -cE "$1" "$2") || [ $? -eq 1 ] || { echo "grep failed on $2" >&2; exit 2; }
	echo "$c"
}
d=$(mktemp); trap 'rm -f "$d"' EXIT
first=1; rc=0
for f in "$@"; do
	bad=0
	objdump -d --no-show-raw-insn -M intel "$f" | sed -E 's/<[^>]*>//g' > "$d"
	n=$(count "$pat" "$d")
	if [ "$n" -ne 0 ]; then
		echo "FAIL $f: $n instruction(s) beyond $level, first ones:"; grep -m5 -E "$pat" "$d"; bad=1
	fi
	if [ "$first" = 1 ]; then
		aes=$(count '\sv?aesenc\s' "$d"); clm=$(count '\sv?pclmul[a-z]*dq\s' "$d")
		if [ "$aes" -eq 0 ] || [ "$clm" -eq 0 ]; then
			echo "FAIL $f: no hardware AES ($aes aesenc) or carry-less multiply ($clm pclmul): the level lost aes/pclmul/avx"; bad=1
		fi
		first=0
	fi
	if [ "$bad" = 0 ]; then echo "ok   $f: no listed instruction beyond $level"; else rc=1; fi
done
exit $rc
