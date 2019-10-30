# -*- coding:utf-8 -*-
import threading
import time
import binascii
import hmac
from hashlib import sha256
import socket
import milenage
import test


 

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
def tcplink(sock, addr):
    #contact with AUSF
    print('Accept new connection from %s:%s...' % addr)
    print('收到来自AUSF的连接')
    sock.send(b'Welcome!\n')
    sock.send(b'欢迎接入UDM！\n')
    while True:
        #data = sock.recv(1024)

        #print(data)

        #if not data or data.decode('utf-8') == 'exit':
         #   break

        #
        ki = '000000012449900000000010123456d8'
        rand = '9fddc72092c6ad036b6e464789315b78'
        sqn = '1234567888d8'
        amf = '8d00'
        op ='cda0c2852846d8eb63a387051cdd1fa5'
        #CACULETEopc
        opc=milenage.MilenageGenOpc(ki,op)
        xres, ck, ik, AUTN, ak =milenage.Milenage(ki, opc, rand, sqn, amf)
        #generate AV
        #AV=rand+xres+ck+ik+AUTN
        #generate K_ausf
        key = ck + ik
        P0 = 'xidian'  # accept from AUSF
        L0 = '06'  # accept from AUSF
        P1 = test.LogicalXOR(sqn, ak)
        L1 = '06'
        K_ausf = binascii.hexlify(KDF_ausf(key, P0, L0, P1, L1))
        P1=rand
        L1='04'
        P2=xres
        L2='04'
        AUTN=binascii.hexlify(AUTN)
        xres_star=binascii.hexlify(KDF_xres(key, P0, L0, P1, L1,P2,L2))
        message=rand+AUTN+xres_star+K_ausf
        print 'the result of message is：\n'
        print message
        #sock.send(message.encode('utf-8'))
        sock.send(message.encode('utf-8'))
        #sock.send(('Hello, %s!' % data.decode('utf-8')).encode('utf-8'))

    #sock.close()
    #print('Connection from %s:%s closed.' % addr)



def main():

    # 首先，创建一个基于IPv4和TCP协议的Socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 监听端口:
    #绑定到本机地址 监听端口9999
    #9999用来和AUSF通信
    s.bind(('127.0.0.1', 9999))
    #调用listen()方法开始监听端口，传入的参数指定等待连接的最大数量：
    s.listen(5)#限制的是同一时刻的请求数 暂时没用
    print('Waiting for connection...')
    print('等待与AUSF连接...')
    #接下来，服务器程序通过一个永久循环来接受来自客户端的连接，accept()
    #会等待并返回一个客户端的连接:

    while True:
        # 接受一个新连接:
        sock, addr = s.accept()
        # 创建新线程来处理TCP连接:
        #该线程绑定到tcplink函数
        t = threading.Thread(target=tcplink, args=(sock, addr))
        t.start()



if __name__ == "__main__":
    main()
