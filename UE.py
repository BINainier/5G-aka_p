# -*- coding:utf-8 -*-
#UE receive rand and AUTN from SEAF, check freshness by AUTN
#Then ues res+ik+ck generate res*
#Send res* to SEAF


import binascii
import hmac
from hashlib import sha256
import socket
import milenage
import random

def Generate_IMSI():
    imsi = '46000'
    for num in range(0,9):
        imsi=imsi + str(random.choice('0123456789'))
    return imsi

#generate SUCI

def Generate_SUCI(imsi):
    mcc = imsi[:3]
    mnc = imsi[3:5]
    msin = imsi[5:]
    suci = '0'+mcc+mnc+'678'+'0'+'0'+msin
    return suci

#send SUCI to seaf
def SendTo_SEAF(data, host, port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(host, port)
    print 'send SUCI to SEAF\n'
    client.send(data)

#resolve AUTN
def AUTN_resolve(AUTN):
    sqn_ak = AUTN[:6]
    amf = AUTN[6:8]
    mac_a = AUTN[8:]
    return sqn_ak, amf, mac_a


#F-function in UE
def milenage_ue(rand, AUTN, ki, op):

    #F5*
    i = 0
    opc = milenage.MilenageGenOpc(ki, op)
    tmp1 = milenage.LogicalXOR(rand, opc)
    tmp2 = milenage.AESEncrypt(ki, tmp1)
    ak_map = {}
    for i in range(16):
        ak_map[(i+4)%16] = milenage.__XOR__(tmp2[i], opc[i])
    ak_map[15] = milenage.__XOR__(ak_map[15], chr(8))
    tmp1 = ''.join(val for val in ak_map.values())
    tmp1 = milenage.AESEncrypt(ki, tmp1)
    ak_star = milenage.LogicalXOR(tmp1, opc)
    
    sqn_ak, amf, mac_a = AUTN_resolve(AUTN)
    res, ck, ik, ak = milenage.MilenageF2345(ki, opc, rand)
    sqn = milenage.LogicalXOR(sqn_ak, ak)
    xmac_a, xmac_s = milenage.MilenageF1(ki, opc, rand, sqn, amf)
    return sqn, res, ck, ik, ak, ak_star, xmac_a, xmac_s, mac_a

#generate res*
def KDF_res_star(ck, ik, P0, L0, rand, res):
    key = ck+ik
    P1 = rand
    L1 = str(len(rand))
    P2 = res
    L2 = str(len(res))
    s = binascii.hexlify('6B' + P0 + L0 + P1 + L1 + P2 + L2)
    tmp=hmac.new(key, s, digestmod=sha256).hexdigest()
    res_star=tmp[32:]
    return res_star

#check MAC
def check_mac(xmac_a, mac_a):
    if xmac_a==mac_a:
        return 1
    else :
        return 0

#check sqn
def check_sqn(sqn):
    pass

#generate auts
def generate_auts(sqn_ms, ak_star, xmac_s):
    tmp = milenage.LogicalXOR(sqn_ms, ak_star)
    auts = tmp+xmac_s
    return auts

def main():
    pass

if __name__ == "__main__":
    pass
