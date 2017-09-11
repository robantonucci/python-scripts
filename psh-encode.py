#!/usr/bin/env python
import base64

def encodePSH(code, arch):
	if arch == 'x86':
		encoded = \
		r"%SystemRoot%\syswow64\WindowsPowerShell\v1.0\powershell.exe \
		-nop -win hidden -noni -enc "\
		+ base64.b64encode(code.encode('utf_16_le'))
	else:
		encoded = "powershell -nop -win hidden -noni -enc " +\
		base64.b64encode(code.encode('utf_16_le'))
	return encoded

x86 = raw_input('[+] Are we using x86 PowerShell on x64 pc? [y/N] ') or 'n'
if x86.lower() == 'y':
	arch = 'x86'
else:
	arch = 'x64'

	
rawpsh = raw_input('[+] Paste the PowerShell command:\n> ')
if not rawpsh:
	print '[-] Nothing to encode..'
	exit(0)
encodedpsh = encodePSH(rawpsh,arch)
print '\n\n[+] Here is your encoded PowerShell goodness!\n\n' + encodedpsh
