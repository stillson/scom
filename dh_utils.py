#!/usr/bin/env python2.7

import gmpy2
from gmpy2 import mpz
from rdrand import Random
from collections import namedtuple
from hashlib import pbkdf2_hmac
from binascii import unhexlify,hexlify
from scom_util import get_time
import threading
import Queue
from time import sleep
import sys
from cdb import cb


DHOffer = namedtuple('DHOffer', 'time a ga gen prime')
Keys    = namedtuple('Keys', 'enc_to_serv auth_to_serv enc_to_cli auth_to_cli')
r       = Random()

class DH_Consts_class:
    def __init__(self):
        self.bits = 1500
        self.glen = 128
        #self.regen_time = 86400
        self.regen_time = 30000
        #self.regen_count = 0
        self.regen_count = 100
        #4 keys, 256 bits long, in bytes
        self.keylen = 4 * 256 / 8
        self.salt = unhexlify('21937ea4c05f2266ef0c40b9ae620bdd')
        self.iters = 2

DH_Consts = DH_Consts_class()

def get_ga(a, gen, prime):
    return gmpy2.powmod(mpz(gen), mpz(a), mpz(prime))

def get_gab(ga,b, prime):
    return gmpy2.powmod(mpz(ga), mpz(b), mpz(prime))

"""
Generating a 2n+1 prime is sloooooow
need to do this
1) ahead of time, possibly caching
2) keep a good supply around
3) but, it makes generators a lot easier (not even, not p)
"""
@cb
def new_prime():
    np = mpz(r.getrandbits(DH_Consts.bits - 1))
    np = gmpy2.next_prime(np)

    while not gmpy2.is_prime(2 * np + 1, 25):
        np = gmpy2.next_prime(np)

    return mpz(2 * np + 1)

def new_gen():
    ng = mpz(0)
    num_ones = r.randint(3,15)
    for _ in range(num_ones):
        ng = ng.bit_set(r.randint(3,DH_Consts.glen))

    # make it odd
    ng += 1

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
    """
    Class to handle background generation of primes.
    needs threads, won't work with coro's
    need to write forking version to work with coros
    """
    def __init__(self):
        cb('init in')
        #self.prime  = new_prime()
        #self.gen    = new_gen()
        self.gen = mpz(2**8 + 1)
        self.prime = mpz(2433034004136191092412452167654890336710943175238024538073355187215113397349339581892962176007364594342185310453788972008559302165276546070920194309429178809519159693243498550714775290623332500291667207915665503996610500529723130409113365908739836642789433072331293857418649991624994652023868040138771467455865235467732066926441164745406537112801241137183782322012844255786185181341130630305131432482835588103455065167417103017978822886589141663438367L)
        self.last_regen = get_time()
        cb('init postgen')
        self.genPQ = Queue.Queue(5) # stash 5 gen/prime pairs for future use
        self.rgThread = threading.Thread(target=self.regenThread)
        self.rgThread.name = 'DHMaster Regen Thread'
        self.rgThread.daemon = True
        self.gpLock = threading.Lock()
        self.use_count = 0
        self.rgThread.start()
        cb('init poststart')
        self.in_regen = 0

    def regenThread(self):
        # runs forever filling Queue
        while True:
            cb('rgt start')
            g = mpz(2**8 + 1)
            p = mpz(2433034004136191092412452167654890336710943175238024538073355187215113397349339581892962176007364594342185310453788972008559302165276546070920194309429178809519159693243498550714775290623332500291667207915665503996610500529723130409113365908739836642789433072331293857418649991624994652023868040138771467455865235467732066926441164745406537112801241137183782322012844255786185181341130630305131432482835588103455065167417103017978822886589141663438367L)
            # this will block until there is space
            cb('rgt post prime')
            self.genPQ.put((g,p))
            cb('rgt put done')

    @cb
    def regen(self):
        with self.gpLock:
            self.in_regen = 1
        gen, prime = self.genPQ.get()
        with self.gpLock:
            self.gen, self.prime = gen, prime
            self.genPQ.task_done()
            self.last_regen = get_time()
            self.use_count = 0
            self.in_regen = 0

    def offer(self):
        now = get_time()
        do_regen = False
        # we really don't want multiple concurrent regen()'s happening
        # in the worst case you could be blocking many threads waiting for
        # a prime. Hence the Queue. It shouldn't be a problem unless you
        # force regen to happen every minute, for example. Then, you
        # can make the queue bigger, and let it fill before continueing
        with self.gpLock:
            if DH_Consts.regen_count:
                self.use_count += 1
            if now - self.last_regen > DH_Consts.regen_time or self.use_count > DH_Consts.regen_count:
                if not self.in_regen:
                    do_regen = True

        if do_regen:
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
        print 1
        np = new_prime()
        print 2
        ng = new_gen()
        print 3
        print np
        print hex(np)
        print hex(ng)

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
