# -*- coding:utf-8 -*-
import threading
import time
import milenage
import binascii
import hmac
from hashlib import sha256
import socket
import random
def Generate_rand():
    rand=''
    for num in range(0,32):
        rand=rand+str(random.choice('0123456789abcdef'))
    return  rand
def Init():
    ki = '000000012449900000000010123456d8'
    #rand = '9fddc72092c6ad036b6e464789315b78'
    rand=Generate_rand()
    sqn = '1234567888d8'
    amf = '8d00'
    op = 'cda0c2852846d8eb63a387051cdd1fa5'
    return ki,rand,sqn,amf,op
def KDF_ausf(key, P0, L0, P1, L1):
    #generate CK', IK'
    appsecret = key
    s = binascii.hexlify('20')+binascii.hexlify(P0)+binascii.hexlify(L0)+binascii.hexlify(P1)+binascii.hexlify(L1)
    print s
    tmp = hmac.new(appsecret, s, digestmod=sha256).digest()
    ck_new = tmp[:32]
    ik_new = tmp[32:]
    key_new = ck_new+ik_new
    K_ausf = hmac.new(key_new, s, digestmod=sha256).digest()
    return K_ausf

def KDF_xres(key, P0, L0, P1, L1,P2,L2):
    #generate Xres_star
    appsecret = key
    s = binascii.hexlify('20' + P0 + L0 + P1 + L1+ P2 + L2 )
    Xres_star=hmac.new(appsecret, s, digestmod=sha256).digest()
    return Xres_star
def SentTo_AUSF(data,host3,port3):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host3, port3))
    print 'send 5g he av To AUSF\n'
    client.send(data)

def main():
    host3='127.0.0.1'
    port3=6001
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 9999))
    server.listen(5)
    print('Waiting for connection...')
    print('等待与AUSF连接...')
    while True:
        sock, addr = server.accept()
        print 'got connected from', addr
        data = sock.recv(1024)
        print 'get data from AUSF:\n'
        print data
        # if not data or data.decode('utf-8') == 'exit':
        #  break
        ki, rand, sqn, amf, op = Init()
        # CACULETEopc
        opc = milenage.MilenageGenOpc(ki, op)
        xres, ck, ik, AUTN, ak = milenage.Milenage(ki, opc, rand, sqn, amf)
        # generate K_ausf
        key = ck + ik
        # P0 = 'xidian'  # accept from AUSF
        # L0 = '06'  # accept from AUSF
        P0 = data
        L0 = str(len(data))
        P1 = milenage.LogicalXOR(sqn, ak)
        L1 = '06'
        K_ausf = binascii.hexlify(KDF_ausf(key, P0, L0, P1, L1))
        P1 = rand
        L1 = '04'
        P2 = xres
        L2 = '04'
        AUTN = binascii.hexlify(AUTN)
        xres_star = binascii.hexlify(KDF_xres(key, P0, L0, P1, L1, P2, L2))
        message = rand + AUTN + xres_star + K_ausf
        print 'the result of message is：\n'
        # rand=32 AUTN= XRE32S_star=64 K_ausf=64
        print message
        print 'the length of message is:' + str(len(message))
        # sock.send(message.encode('utf-8'))
        SentTo_AUSF(message,host3,port3)
if __name__ == "__main__":
    main()
