import milenage
import binascii
import hmac
from hashlib import sha256
import socket
import random
 

def KDF(keyset, P0, L0):
    ki   = binascii.unhexlify(keyset['ki'])
    op   = binascii.unhexlify(keyset['op'])
    rand = binascii.unhexlify(keyset['rand'])
    sqn = binascii.unhexlify(keyset['sqn'])
    amf = binascii.unhexlify(keyset['amf'])
    opc = milenage.MilenageGenOpc(ki, op)
    xres, ck, ik, ak = milenage.MilenageF2345(ki, opc,rand)
    xres, ck, ik, AUTN= milenage.Milenage(ki, opc, rand, sqn, amf)

    P1 = milenage.LogicalXOR(sqn, ak)
    L1 = milenage.LogicalXOR(sqn, '06')
    #generate CK', IK'
    key = ck+ik
    appsecret = key

    s = '20'+P0+L0+P1+L1
    
    tmp = hmac.new(appsecret, s, digestmod=sha256).digest()
    ck_new = tmp[:6]
    ik_new = tmp[6:]

    key_new = ck_new+ik_new

    K_ausf = hmac.new(key_new, s, digestmod=sha256).digest()

    
def main():
    pass

if __name__ == "__main__":
    main()
