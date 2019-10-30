# -*- coding:utf-8 -*-
#
# AUSF receive 5G_HE_AV from UDM, generate K_seaf, HXRES* and replace them in 5G_HE_AV, turn 5G_HE_AV to 5G_AV

import milenage
import binascii
import hmac
from hashlib import sha256
import socket
import random



def KDF_seaf(K_ausf, P0, L0):
    # generate K_seaf
    s = binascii.hexlify('20'+P0+L0)
    key = K_ausf
    K_seaf = hmac.new(key, s, digestmod=sha256).digest()
    return K_seaf

def KDF_hxres_star(xres_star, rand):
    s = binascii.hexlify(rand+xres_star)
    tmp = sha256()
    tmp.update(s)
    value = tmp.hexdigest()
    hxres_star = value[32:]
    return hxres_star






