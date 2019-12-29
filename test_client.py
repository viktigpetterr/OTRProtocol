#!/usr/bin/python3

# OTR Doc: https://otr.cypherpunks.ca/Protocol-v3-4.1.1.html
import socket
import random
import hashlib

def diffieHellmanExchange(soc, p, g):
    print("\nDiffie-Hellman:")
    ## receive g**x1
    # receive the hex-string, decode, and remove trailing '\n'
    g_x1 = soc.recv(4096).decode('utf8').strip()
    # interpret as a number
    g_x1 = int(g_x1, 16)
    # generate g**x2, x2 shall be a random number
    x2 = random.getrandbits(128)
    # calculate g**x2 mod p
    g_x2 = pow(g, x2, p)
    # convert to hex-string
    g_x2_str = format(g_x2, 'x')
    # send it
    soc.send(g_x2_str.encode('utf8'))
    # read the ack/nak. 
    print ('\tsent g_x2:', soc.recv(4096).decode('utf8').strip())

    g_x1x2 = pow(g_x1, x2, mod = p)

    sha1 = hashlib.sha1()
    sha1.update(g_x1x2.to_bytes((g_x1x2.bit_length() + 7) // 8, 'big') ) # @ WARNING: Might be in base 10  format. 
    sha1.update(bytes('eitn41 <3', encoding = 'utf-8'))
    secret = sha1.hexdigest()
    print("\tCommon secret: ", secret)

    return (g_x1x2, secret) 

def socialistMillionare(soc, p, g, secret):
    print('\nSocialist Millionare:')
    g_a2 = soc.recv(4096).decode('utf8').strip()
    g_a2 = int(g_a2, 16)
    # generate g**b2, b2 shall be a random number
    b2 = random.getrandbits(128)
    # calculate g**b2 mod p
    g_b2 = pow(g, b2, p)
    # convert to hex-string
    g_b2_str = format(g_b2, 'x')
    g2 = pow(g_a2, b2, mod = p)
    # send it
    soc.send(g_b2_str.encode('utf8'))
    print ('\tsent g_b2:', soc.recv(4096).decode('utf8').strip())
    #----------------------------------

    g_a3 = soc.recv(4096).decode('utf8').strip()
    g_a3 = int(g_a3, 16)
    b3 = random.getrandbits(128)
    g_b3 = pow(g, b3, p)
    g3 = pow(g_a3, b3, mod = p)
    g_b3_str = format(g_b3, 'x')
    soc.send(g_b3_str.encode('utf8'))
    print ('\tsent g_b3:', soc.recv(4096).decode('utf8').strip())
    #----------------------------------

    P_a = soc.recv(4096).decode('utf8').strip()
    P_a = int(P_a, 16)
    r = random.getrandbits(128)
    P_b = pow(g3, r, mod = p)
    P_b_str = format(P_b, 'x')
    soc.send(P_b_str.encode('utf8'))
    print ('\tsent P_b:', soc.recv(4096).decode('utf8').strip())
    #----------------------------------

    Q_a = soc.recv(4096).decode('utf8').strip()
    Q_a = int(Q_a, 16)
    Q_b = pow(pow(g, r, mod = p) * pow(g2, secret, mod = p), 1, mod = p)
    Q_b_str = format(Q_b, 'x')
    soc.send(Q_b_str.encode('utf8'))
    print ('\tsent Q_b:', soc.recv(4096).decode('utf8').strip())
    #----------------------------------

    R_a = soc.recv(4096).decode('utf8').strip() 
    R_a = int(R_a, 16)
    Q_b_inv = pow(Q_b, -1, mod = p) 
    R_b = pow(Q_a * Q_b_inv, b3, mod = p)
    R_ab = pow(R_a, b3, mod = p)

    R_b_str = format(R_b, 'x')
    soc.send(R_b_str.encode('utf8'))
    print ('\tsent R_b:', soc.recv(4096).decode('utf8').strip())
    #----------------------------------
    status = soc.recv(4096).decode('utf8').strip()
    print ('\tAuthentication:', status)
    cond = pow(P_a * pow(P_b, -1, mod = p), 1, mod = p)

    if(status == 'ack' and R_ab == cond):
        return True
    else:   
        return False

def sendMessage(message, DHKey, soc):
    print('\nChat:')
    print('\tMessage:', message)
    enc_msg = int(message, 16) ^ DHKey
    enc_msg_str = format(enc_msg, 'x')
    soc.send(enc_msg_str.encode('utf8'))
    print('\tResponse:', soc.recv(4096).decode('utf8').strip())

if __name__ == "__main__":
    message = '0123456789abcdef'
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
    soc.connect(("eitn41.eit.lth.se", 1337))

    # the p shall be the one given in the manual
    p = int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF', 16)
    g = 2
    DHKey, secret = diffieHellmanExchange(soc, p, g)
    secure = socialistMillionare(soc, p, g, int(secret, 16))
    if(secure):
        sendMessage(message, DHKey, soc)






