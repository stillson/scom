from time import time
from binascii import unhexlify, hexlify
import sys
from rdrand import Random
r = Random()

def get_time():
    return int(time())

# works on mpz too
def int_to_bytes(int):
    s = '%x' % int
    if len(s) % 2 == 1: s = '0' + s
    return unhexlify(s)

def clean_unhexlify(s):
    if len(s) % 2 == 1: s = '0' + s
    return unhexlify(s)

def bytes_to_int(bytes):
    return int(hexlify(bytes), 16)

class FreeHolder(object):
    def __init__(self, *args):
        if len(args) == 1:
            args = args[0].split()
        for field in args:
            self.__dict__[field] = None

class Holder(FreeHolder):
    def __getattr__(self, arg):
        if arg not in self.__dict__:
            raise KeyError
        return self.__dict__[arg]

    def __setattr__(self, arg, val):
        if arg not in self.__dict__:
            raise KeyError
        self.__dict__[arg] = val

class IHolder(Holder):
    def __getattr__(self, arg):
        if arg.endswith('i') and arg[:-1] in self.__dict__:
            return bytes_to_int(self.__dict__[arg[:-1]])
        if arg not in self.__dict__:
            raise KeyError
        return self.__dict__[arg]

    def __setattr__(self, arg, val):
        if arg not in self.__dict__:
            raise KeyError
        self.__dict__[arg] = val

def pad(a_str, block_size):
    # pad out to block len, unsing pkcs7
    pad_len     = block_size - (len(a_str) % block_size)
    return        a_str + (chr(pad_len) * pad_len)

def depad(a_str):
    padlen = ord(a_str[-1])
    return a_str[:-padlen]

def get_iv():
    # returns random IV
    return unhexlify('%032x' % r.getrandbits(128))

def byte_time():
    return unhexlify('%x' % get_time())

