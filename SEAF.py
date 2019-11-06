# -*- coding:utf-8 -*-
#SEAF receive 5G_AV from AUSF
#send rand, AUTN to UE
#receive res* from UE, generate hres*
#verificate hres* and hxres*


import milenage
import binascii
import hmac
from hashlib import sha256
import socket
import random


#generate hres*
def KDF_hres_star(rand, res_star):
    s = binascii.hexlify(rand+res_star)
    tmp = sha256()
    tmp.update(s)
    value = tmp.hexdigest()
    hres_star = value[32:]
    return hres_star

#generate K_amf
def KDF_Kamf(K_seaf, supi):
    P0 = supi
    L0 = str(len(supi))
    P1 = '0000'
    L1 = str(len(P1))
    s = binascii.hexlify('6D'+P0+L0+P1+L1)
    K_amf = hmac.new(K_seaf, s, digestmod=sha256).hexdigest()
    return K_amf

