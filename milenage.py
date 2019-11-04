# -*- coding:utf-8 -*-
import sys
import binascii
from   Crypto.Cipher import AES
from itertools import izip



#Our macro
__XOR__ = lambda x, y: chr(ord(x) ^ ord(y)) 


def LogicalXOR(str1, str2):
    '''Function to XOR two strings'''
    return ''.join(__XOR__(x, y) for (x,y) in izip(str1, str2))


def AESEncrypt(key, buf):
    '''Encrypt buffer using AES-SHA1 128 algorithm
       @key: Key to be used for encryption
       @buf: Buffer to be encrypted'''
    encryptor = AES.new(key, AES.MODE_CBC)
    return encryptor.encrypt(buf)


def MilenageGenOpc(ki, op):
    '''Generate Opc using Ki and Op
       @ki: 128-bit subscriber key
       @op: 128-bit operator variant'''
    opc = AESEncrypt(ki, op)
    return LogicalXOR(opc, op)


#MilenageF1(add)
def MilenageF1(ki, opc, rand, sqn, amf):
    '''Milenage F1 algoritms'''
    i = 0
    tmp1 = LogicalXOR(rand, opc)
    tmp1 = AESEncrypt(ki, tmp1)
    tmp2 = sqn[:6] + amf[:2]
    tmp2 = tmp2 + tmp2[:8]
    tmp3_map = {}
    for i in range(16):
        tmp3_map[(i+8)%16] = __XOR__(tmp2[i], opc[i])
    tmp3 = ''.join(val for val in tmp3_map.values())
    tmp3 = LogicalXOR(tmp3, tmp1)
    tmp1 = AESEncrypt(ki, tmp2)
    tmp1 = LogicalXOR(tmp1, opc)
    mac_a = tmp1[:8]   #网络鉴权码 network authentication code，一般鉴权时作为MAC值
    mac_s = tmp1[8:]   #重同步鉴权码 resynchronisation authentication code，重同步鉴权时作为MAC值
    return mac_a, mac_s


def MilenageF2345(ki, opc, rand):
    '''Milenage f2, f3, f4, f5, f5* algorithms'''
    i = 0
    tmp1 = LogicalXOR(rand, opc)
    tmp2 = AESEncrypt(ki, tmp1)
    tmp1 = LogicalXOR(tmp2, opc)
    tmp1 = tmp1[:15] + chr(ord(tmp1[15]) ^ 1)
    tmp3 = AESEncrypt(ki, tmp1)
    tmp3 = LogicalXOR(tmp3, opc)
    xres  = tmp3[8:]
    ak = tmp3[:6]
    

    #F3 - to calculate ck
    ck_map = {}
    for i in range(16):
        ck_map[(i+12)%16] = __XOR__(tmp2[i], opc[i])
    ck_map[15] = __XOR__(ck_map[15], chr(2))
    tmp1 = ''.join(val for val in ck_map.values())
    ck = AESEncrypt(ki, tmp1)
    ck = LogicalXOR(ck, opc)

    #F4 - to calculate ik
    ik_map = {}
    for i in range(16):
        ik_map[(i+8)%16] = __XOR__(tmp2[i], opc[i])
    ik_map[15] = __XOR__(ik_map[15], chr(4))
    tmp1 = ''.join(val for val in ik_map.values())
    ik = AESEncrypt(ki, tmp1)
    ik = LogicalXOR(ik, opc)


    return xres, ck, ik, ak


def Milenage(ki, opc, rand, sqn, amf):
    mac_a, mac_s = MilenageF1(ki, opc, rand, sqn, amf)
    xres, ck, ik, ak = MilenageF2345(ki, opc,rand)
    AUTN = LogicalXOR(sqn[:6], ak)  #ak:6
    AUTN = AUTN+amf[:2]+mac_a   #amf取2位, mac_a:8
    return xres, ck, ik, AUTN, ak


def GenerateQuintuple(keyset):
    ki   = binascii.unhexlify(keyset['ki'])
    op   = binascii.unhexlify(keyset['op'])
    rand = binascii.unhexlify(keyset['rand'])
    sqn = binascii.unhexlify(keyset['sqn'])
    amf = binascii.unhexlify(keyset['amf'])

    #Generate opc from ki and op
    opc = MilenageGenOpc(ki, op)

    #Get xres, ck, ik, AUTN
    xres, ck, ik, AUTN,ak = Milenage(ki, opc, rand, sqn, amf)

    #Store values now
    keyset['opc']  = binascii.hexlify(opc)
    keyset['xres']   = binascii.hexlify(xres)
    keyset['ck'] = binascii.hexlify(ck)
    keyset['ik'] = binascii.hexlify(ik)
    keyset['AUTN'] = binascii.hexlify(AUTN)
    return


def ReadMilenageInput(filename):
    attribs = []
    keyset  = {}
    try:
       fp = open(filename)
    except:
       print 'Error opening file %s'%(filename)
       sys.exit()

    for line in fp.readlines():
        if line.startswith('#'):
            continue
        # if line.startswith('\n'):
        #     if len(keyset):
        #         attribs.append(keyset)
        #         keyset = {}
        #     continue
        keyset = {}
        attribs.append(keyset)

        key, value = line.split('=')
        keyset[key] = value.split('\n')[0]
    # print(attribs)

    #Validate input
    if len(attribs) == 0:
       print 'Milenage: Please provide KI/OP/RAND in input file'
       sys.exit()

    # for keyset in attribs:
    #    if not keyset.__contains__('ki') or \
    #       not keyset.__contains__('op') or \
    #       not keyset.__contains__('rand'):
    #       print ('Milenage: KI or OP missing in keyset')
    #       sys.exit()

    return attribs


def PrintMilenageOutput(attribs):
    '''Prints input read'''
    idx = 1
    for keyset in attribs[4]:
       print 'Keyset # %d'%(idx)
       print '  %2s: %s'%('ki', keyset['ki']) 
       print '  %2s: %s'%('op', keyset['op']) 
       print '  %2s: %s'%('sqn', keyset['sqn']) 
       print '  %2s: %s'%('amf', keyset['amf']) 
       print '  Auth Quintuple: '
       print '    %4s: %s'%('rand', keyset['rand']) 
       print '    %4s: %s'%('xres', keyset['xres']) 
       print '    %4s: %s'%('ck',   keyset['ck']) 
       print '    %4s: %s'%('ik',   keyset['ik']) 
       print '    %4s: %s'%('AUTN',   keyset['AUTN']) 
       print ''
       idx += 1 
    return
    

def main():
    '''The main function'''
    if len(sys.argv) < 2:
       print 'Milenage: Please provide input file'
       return

    #Read input
    attribs = ReadMilenageInput(sys.argv[1])

    #Generate auth triplets now
    for keyset in attribs:
        GenerateQuintuple(keyset)

    #Print output
    PrintMilenageOutput(attribs)
    return


if __name__ == '__main__':
    main()
