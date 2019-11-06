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
    # P0 seiving net work name
    #P1 length of network name
    s = binascii.hexlify('6C'+P0+L0)
    key = K_ausf
    K_seaf = hmac.new(key, s, digestmod=sha256).hexdigest()
    return K_seaf

def KDF_hxres_star(xres_star, rand):
    s = binascii.hexlify(rand+xres_star)
    tmp = sha256()
    tmp.update(s)
    value = tmp.hexdigest()
    hxres_star = value[32:]
    return hxres_star

def HE_AV_resolve(data):
    rand=data[:32]
    autn=data[32:64]
    xres_star=data[64:96]
    K_ausf=data[96:]
    return rand, autn, xres_star, K_ausf

def Generate_AV(rand,autn,hxres_star,K_seaf):
    AV=rand+autn+hxres_star+K_seaf
    return AV



def SentTo_UDM(data,host3,port3):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(host3, port3)
    print 'send SNname To UDM\n'
    client.send(data)

def SentTo_SEAF(data,host2,port2):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(host2, port2)
    print 'send 5g AV To SEAF\n'
    client.send(data)


# def 



def main():
    host = ''  #  AUSF Server IP
    host2 = '127.0.0.1'  # SEAF Server IP
    host3='127.0.0.1' # UDM Server IP
    port = 6001  # AUSF Server Port
    port2 = 7001  # SEAF Server Port
    port3=9999 # UDM ServerPort
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    #listen to port 6001
    server.listen(5)
    print('Waiting for connection...')
    print('等待与SEAF和UDM连接...')
    while True:
        while True:
            sock, addr = server.accept()
            print 'got connected from', addr
            data = sock.recv(1024)
            length = len(data)
            if length <= 10:
                global P0
                P0 = data
                global L0
                L0 = str(len(data))
                print 'accept sn name from seaf'
                print 'sn name is:' + data
                SentTo_UDM(data, host3, port3)  # send it to UDM
            elif length == 192:
                print 'accept 5g HE AV from UDM'
                global xres_star
                xres_star = 0
                rand, autn, xres_star, K_ausf = HE_AV_resolve(data)
                K_seaf = binascii.hexlify(KDF_seaf(K_ausf, P0, L0))

                hxres_star = binascii.hexlify(KDF_hxres_star(xres_star, rand))
                AV = Generate_AV(rand, autn, hxres_star, K_seaf)
                print 'length is:' + len(AV)
                print 'the result of Av is' + AV

                SentTo_SEAF(AV, host2, port2)
            elif length == 32:
                print 'accept Xres* from SEAF'
                if str(data) == str(xres_star):  # 检验接收到的res*
                    message = 'successful'
                    SentTo_SEAF(message, host2, port2)

if __name__ == "__main__":
    main()


