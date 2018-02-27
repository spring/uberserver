#!/usr/bin/python3
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import SayHooks

if len(sys.argv) < 2:
	print("Usage: %s nick ..." %(sys.argv[0]))
	sys.exit(-1)
tocheck = sys.argv[1]


for check in sys.argv[1:]:
	if SayHooks.isNasty(check):
		print("Is Nasty: %s" % (check))
	for nick in SayHooks.bad_nick_list:
		if nick in check.lower():
			print("%s is in nasty word list: %s" %(nick, check))

