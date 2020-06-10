import socket
import time
import random
import hmac

from ecc.Key import Key
from hashlib import sha256,md5
from ecc.elliptic import mul

DOMAINS = {
    # Bits : (p, order of E(GF(P)), parameter b, base point x, base point y)
    192: (0xfffffffffffffffffffffffffffffffeffffffffffffffff,
          0xffffffffffffffffffffffff99def836146bc9b1b4d22831,
          0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1,
          0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012,
          0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811),

    224: (0xffffffffffffffffffffffffffffffff000000000000000000000001,
          0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d,
          0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4,
          0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21,
          0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34),

    256: (0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
          0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
          0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
          0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
          0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5),

    384: (0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
          0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
          0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
          0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
          0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f),

    521: (
    0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
    0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409,
    0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00,
    0x0c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,
    0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650)
}

if __name__ == '__main__':

    global Ta,Rb,p,n,b,x,y,c_p,c_q,c_n,M1,M2,M3,Kb

    HOST = '192.168.31.253'
    PORT = 9002

    # initialization
    p, n, b, x, y=DOMAINS[256]
    c_p=3
    c_n=p
    c_q=p-b

    idA='00000001'
    idB='00000002'
    token=0

    print('Begin')

    #TCP link
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.bind((HOST,PORT))

    print('Listen to the connection from client...')
    sock.listen(5)
    try:
        while (token==0):
            connection, address = sock.accept()
            print('Connected. Got connection from ', address)

            # 2. B receive M1 from A,generate my keypair, generate Nb, compute Cb, send M2
            M1=connection.recv(1024).decode()
            PKax=M1.split(',')[0]
            PKay=M1.split(',')[1]
            PKa=(int(PKax),int(PKay))

            time1 = time.time()
            keypair = Key.generate(521)
            PKbx = keypair._pub[1][0]
            PKby = keypair._pub[1][1]
            SKb = keypair._priv[1]

            # generate random number Rb1
            Rb1 = random.randint(1, 100)
            while True:
                if SKb % Rb1 == 0:
                    break
                else:
                    Rb1 = random.randint(1, 100)
            # calculate random number Rb2
            Rb2 = int(SKb // Rb1)

            # calculate the same shared key
            Kb1 = mul(c_p, c_q, c_n, PKa, Rb1)
            Kb = mul(c_p, c_q, c_n, Kb1, Rb2)

            Nb=random.randint(000000,999999)
            stringcb=str(PKbx)+PKax+str(Nb)
            newmd5=md5()
            newmd5.update(stringcb.encode())
            cb=newmd5.hexdigest()
            time2 = time.time()

            M2=str(PKbx)+','+str(PKby)+','+cb
            connection.send(M2.encode())

            # 4. B receive M3=Na, send M4=Nb, compute and show digb
            M3=connection.recv(1024).decode()
            Na=int(M3)
            M4=str(Nb)
            connection.send(M4.encode())

            time3 = time.time()
            hmac_string=str(PKax)+str(PKbx)+str(Na)+str(Nb)
            newhash=hmac.new(str(Kb[0]).encode(),''.encode(),sha256)
            newhash.update(hmac_string.encode())
            digb=newhash.hexdigest()[0:4]
            time4 = time.time()
            time = (time4 - time3) + (time2 - time1)
            print('sum time:', time)
            print('digest is',digb)
            print('the shared secret is', Kb)           
            token=1

    except KeyboardInterrupt:
        print('>>>quit')
