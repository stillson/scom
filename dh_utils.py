#!/usr/bin/env python2.7

import gmpy2
from gmpy2 import mpz
from rdrand import Random
from collections import namedtuple
from hashlib import pbkdf2_hmac
from binascii import unhexlify,hexlify
from scom_util import get_time
DHOffer = namedtuple('DHOffer', 'time a ga gen prime')
Keys    = namedtuple('Keys', 'enc_to_serv auth_to_serv enc_to_cli auth_to_cli')
r       = Random()

class DH_Consts_class:
    def __init__(self):
        self.bits = 1500
        self.glen = 128
        self.regen_time = 86400
        #4 keys, 256 bits long, in bytes
        self.keylen = 4 * 256 / 8
        self.salt = unhexlify('21937ea4c05f2266ef0c40b9ae620bdd')
        self.iters = 2

DH_Consts = DH_Consts_class()

def get_ga(a, gen, prime):
    return gmpy2.powmod(mpz(gen), mpz(a), mpz(prime))

def get_gab(ga,b, prime):
    return gmpy2.powmod(mpz(ga), mpz(b), mpz(prime))

def new_prime():
    np = mpz(r.getrandbits(DH_Consts.bits))
    np = gmpy2.next_prime(np)

    while not gmpy2.is_prime(np, 40):
        np = gmpy2.next_prime(np)

    return mpz(np)

def new_gen():
    ng = mpz(0)
    num_ones = r.randint(3,15)
    for _ in range(num_ones):
        ng = ng.bit_set(r.randint(0,DH_Consts.glen))

    return mpz(ng)

def new_a():
    return mpz(r.getrandbits(DH_Consts.bits))

def mpz_to_bytes(an_mpz):
    h_mpz = an_mpz.digits(16)
    if len(h_mpz) % 2 == 1: h_mpz = '0' + h_mpz
    return unhexlify(h_mpz)

def bytes_to_mpz(a_buf):
    return mpz(hexlify(a_buf), base=16)

def get_keys_from_gab(gab_mpz):
    buf = mpz_to_bytes(gab_mpz)
    keybuf = pbkdf2_hmac('sha256', buf, DH_Consts.salt, DH_Consts.iters, DH_Consts.keylen)
    return Keys(keybuf[:32], keybuf[32:64], keybuf[64:96], keybuf[96:])


class DHServer:
    def __init__(self, dhoffer):
        self.dhoffer = dhoffer
        self.keys = None

    @property
    def time(self):
        return self.dhoffer.time

    @property
    def ga(self):
        return self.dhoffer.ga

    @property
    def gen(self):
        return self.dhoffer.gen

    @property
    def prime(self):
        return self.dhoffer.prime

    def getKeys(self, resp=None):
        if not self.keys and not resp:
            raise Exception("Can't get keys yet")
        if not self.keys:
            gab = get_gab(resp, self.dhoffer.a, self.dhoffer.prime)
            self.keys = get_keys_from_gab(gab)
        return self.keys

class DHMaster:
    def __init__(self):
        self.prime  = new_prime()
        self.gen    = new_gen()
        self.last_regen = get_time()

    def regen(self):
        self.prime = new_prime()
        self.gen   = new_gen()
        self.last_regen = get_time()

    def offer(self):
        now = get_time()
        if now - self.last_regen > DH_Consts.regen_time:
            self.regen()
        na = new_a()
        nga = get_ga(na, self.gen, self.prime)
        return DHServer(DHOffer(now, na, nga, self.gen, self.prime))

class DHClient:
    def __init__(self):
        self.b = new_a()
        self.genEb = None
        self.genEa = None
        self.gab   = None
        self.gen   = None
        self.prime = None
        self.keys  = None

    def handleOffer(self, time, ga, gen, prime):
        #valiadate time
        if abs(get_time() - time) >  DH_Consts.regen_time:
            raise "Old gen/prime pair"
        self.gen = gen
        self.prime = prime
        self.genEa = ga
        self.genEb = get_ga(self.b, gen, prime)
        return self.genEb

    def getKeys(self):
        if not self.keys:
            self.gab = get_gab(self.genEa, self.b, self.prime)
            self.keys = get_keys_from_gab(self.gab)
        return self.keys

if __name__ == '__main__':
    if False:
        np = new_prime()
        ng = new_gen()
        a  = new_a()
        b  = new_a()

        print np
        print np.digits(16)
        print
        print ng
        print ng.digits(16)
        print '-' * 40
        print a
        print b
        print '-' * 40
        ga = get_ga(a,ng,np)
        gb = get_ga(b,ng,np)
        print ga
        print
        print gb
        print '-'*40
        gab1 = get_gab(ga,b,np)
        gab2 = get_gab(gb,a,np)
        print gab1
        print
        print gab2
        print '=' * 40
        print gab1 - gab2

    if True:
        import sys

        sys.stderr.write('a\n')
        dhm = DHMaster()

        def exchange(dhm):
            server = dhm.offer()
            cli = DHClient()
            resp = cli.handleOffer(server.time, server.ga, server.gen, server.prime)
            sk = server.getKeys(resp)
            ck = cli.getKeys()
            if sk.enc_to_serv == ck.enc_to_serv:
                sys.stderr.write('.')
            else:
                sys.stderr.write('X')

        sys.stderr.write('b\n')

        for i in range(1000):
            if i % 60 == 0: sys.stderr.write('\n')
            exchange(dhm)

        sys.stderr.write('\nc\n')
