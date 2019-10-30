# -*- coding:utf-8 -*-
import milenage
import binascii
import hmac
from  milenage import GenerateQuintuple
from hashlib import sha256
import socket
import random
 

def KDF_udm(key, P0, L0, P1, L1):
    #generate CK', IK'

    appsecret = key

    s = binascii.hexlify('20'+P0+L0+P1+L1)
    tmp = hmac.new(appsecret, s, digestmod=sha256).digest()
    ck_new = tmp[:32]
    ik_new = tmp[32:]

    key_new = ck_new+ik_new

    K_ausf = hmac.new(key_new, s, digestmod=sha256).digest()
    return K_ausf

    
def main():

    ki='000000012449900000000010123456d8'
    opc='cda0c2852846d8eb63a387051cdd1fa5'
    rand='9fddc72092c6ad036b6e464789315b78'
    sqn='1234567888d8'
    amf='8d00'

    xres, ck, ik, AUTN, ak = milenage.Milenage(ki, opc, rand, sqn, amf)


    key = ck + ik
    P0 = 'xidian'
    L0 = '06'
    P1 = milenage.LogicalXOR(sqn, ak)
    L1= '06'
    K_ausf=KDF_udm(key, P0, L0, P1, L1)
    print  binascii.hexlify(K_ausf)




if __name__ == "__main__":
    main()
