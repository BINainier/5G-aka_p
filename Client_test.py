# -*- coding:utf-8 -*-
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# create connection
s.connect(('127.0.0.1', 9999))
#send SUPI
data='xidian'
#s.send(data.encode('utf-8'))
s.send(data)

# print 5g HE AV
while True:
    print 'accept 5g HE AV from UDM:\n'+s.recv(1024)

#for data in [b'Michael', b'Tracy', b'Sarah']:

 #   s.send(data)

#s.send(b'exit')
#s.close()
