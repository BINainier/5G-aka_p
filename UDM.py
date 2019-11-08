# -*- coding:utf-8 -*-
import threading
import time
import milenage
import binascii
import hmac
from hashlib import sha256
import socket
import random

#reveive SUCI, decrypt and generate SUPI
def SUPI(suci):#suci length:21 supi length:
    mcc = suci[1:4]#3
    mnc = suci[4:6]#2
    msin = suci[11:]#10
    supi = mcc+mnc+msin
    return supi#15

def Generate_rand():
    rand=''
    for num in range(0,32):
        rand=rand+str(random.choice('0123456789abcdef'))
    return  rand

def KDF_ausf(key, P0, L0, P1, L1):
    #generate CK', IK'
    appsecret = key
    s = binascii.hexlify('6A'+P0+L0+P1+L1)
    print s
    tmp = hmac.new(appsecret, s, digestmod=sha256).hexdigest()
    ck_new = tmp[:32]
    ik_new = tmp[32:]
    key_new = ck_new+ik_new
    K_ausf = hmac.new(key_new, s, digestmod=sha256).hexdigest()
    return K_ausf

def KDF_xres(key, P0, L0, P1, L1,P2,L2):
    #generate Xres_star
    appsecret = key
    s = binascii.hexlify('6B' + P0 + L0 + P1 + L1+ P2 + L2 )
    tmp=hmac.new(appsecret, s, digestmod=sha256).hexdigest()
    xres_star=tmp[32:]
    print xres_star
    return xres_star

def SentTo_AUSF(data,host,port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))
    print 'send 5g he av To AUSF\n'
    client.send(data)
    client.close()

def receive_from_AUSF(port):
    HOST = ''
    PORT = port
    ADDR = (HOST, PORT)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)
    server.listen(5)
    while True:
        print 'Waiting for connection...'
        tcpCliSock,addr = server.accept()
        print 'Waiting for connection...'
        print'Waiting for connection with AUSF...'
        print 'got connected from', addr
        #global data
        #data = 0
        data = tcpCliSock.recv(1024)
        tcpCliSock.close()
        server.close()
        print 'get data from AUSF:\n'
        print data
        return data
        #if not data:
         #   break
        
    #     tcpCliSock.close()
    # server.close()

def Init():
    ki = '000000012449900000000010123456d8'
    #rand = '9fddc72092c6ad036b6e464789315b78'
    rand=Generate_rand()
    sqn = '1234567888d8'
    amf = '8d00'
    op = 'cda0c2852846d8eb63a387051cdd1fa5'
    return ki,rand,sqn,amf,op

def main():
    data=receive_from_AUSF(9999)
    data=str(data)
    suci = data[:21]
    supi = SUPI(suci)
    ki, rand, sqn, amf, op = Init()
    opc = milenage.MilenageGenOpc(ki, op)
    xres, ck, ik, AUTN, ak = milenage.Milenage(ki, opc, rand, sqn, amf)
    # generate K_ausf
    key = ck + ik
    # P0 = 'xidian'  # accept from AUSF
    # L0 = '06'  # accept from AUSF
    P0 = str(data)[21:]
    L0 = str(binascii.hexlify(str(len(P0))))
    P1 = milenage.LogicalXOR(sqn, ak)
    L1 = '06'
    K_ausf = KDF_ausf(key, P0, L0, P1, L1)

    #generate xres*
    P1 = rand
    L1 = '08'
    P2 = xres
    L2 = '04'
    AUTN = binascii.hexlify(AUTN)
    print ''
    xres_star = KDF_xres(key, P0, L0, P1, L1, P2, L2)
    print str(len(rand))+' '+str(len(AUTN))+' '+str(len(xres_star))+'0'+str(len(K_ausf))
   
    HE_AV = rand + AUTN + xres_star + K_ausf
    print 'the result of HE_AV is：\n'
    # rand=32 AUTN=32 XRES_star=32 K_ausf=64
    print HE_AV#160
    print 'the length of HE_AV is:' + str(len(HE_AV))
    host3='127.0.0.1'
    port3=6001
    message=str(HE_AV)+str(supi)
    SentTo_AUSF(message,host3,port3)

    
if __name__ == "__main__":
    main()
