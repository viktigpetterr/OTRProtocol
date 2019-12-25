#!/usr/bin/python3
 # OTR Doc: https://otr.cypherpunks.ca/Protocol-v3-4.1.1.html
import socket

soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
soc.connect(("eitn41.eit.lth.se", 1337))

# the p shall be the one given in the manual
p = int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF', 16)
g = 2

##########################
#### D-H Key Exchange ####
##########################

## receive g**x1
# receive the hex-string, decode, and remove trailing '\n'
g_x1 = soc.recv(4096).decode('utf8').strip()
print ('g**x1:', g_x1)
# interpret as a number
g_x1 = int(g_x1, 16)

# generate g**x2, x2 shall be a random number
x2 = 0
# calculate g**x2 mod p
g_x2 = pow(g, x2, p)
# convert to hex-string
g_x2_str = format(g_x2, 'x')
# send it
soc.send(g_x2_str.encode('utf8'))
# read the ack/nak. This should yield a nak due to x2 being 0
print ('\nsent g_x2:', soc.recv(4096).decode('utf8').strip())
