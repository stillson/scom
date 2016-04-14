#!/usr/bin/env python

from cdb import cb
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256, HMAC
from binascii import unhexlify

#data passed in as buffers

VSEP = '####'


# Experimental. Depends on faking an OID...
# use an HMAC for signature to avoid problems with collisions
#HMAC_MIT = None
HMAC_MIT = unhexlify('2d20fa92741ab59b4bab87dd197dfef0840ee0d1dc2b9da3822592dd4363a818')
FAKE_OID = unhexlify('2a864e87850e0209')

def sign_msg(key, msg):
    if HMAC_MIT:
        h = HMAC.new(HMAC_MIT, msg=msg, digestmod=SHA256)
        h.oid = FAKE_OID
    else:
        h = SHA256.new(msg)
    signer = PKCS1_v1_5.new(key)
    sig = signer.sign(h)
    return sig

def verify_msg(key, msg, sig):
    if HMAC_MIT:
        h = HMAC.new(HMAC_MIT, msg=msg, digestmod=SHA256)
        h.oid = FAKE_OID
    else:
        h = SHA256.new(msg)

    verifier = PKCS1_v1_5.new(key)
    if verifier.verify(h, sig):
        return True
    return False

def sign_offer(priv, time, id, genEa, gen, prime):
    message = VSEP.join([time, id, genEa, gen, prime])
    return sign_msg(priv, message)

def sign_response(priv, id, genEb):
    message = VSEP.join([id, genEb])
    return sign_msg(priv, message)


def verify_offer(pub, time, id, genEa, gen, prime, sig):
    message = VSEP.join([time, id, genEa, gen, prime])
    return verify_msg(pub, message, sig)

def verify_response(pub, id, genEb, sig):
    message = VSEP.join([id, genEb])
    return verify_msg(pub, message, sig)

if __name__ == '__main__':
    from pk_util import KeyStore
    from binascii import hexlify

    ks = KeyStore()
    ks.loadStore()

    s = sign_offer(ks.getMine().key, 'asdf', 'asdf', 'asdf', 'asdf', 'asdf')
    print hexlify(s)
    print verify_offer(ks.getMine().key, 'asdf', 'asdf', 'asdf', 'asdf', 'asdf', s)

    s = sign_response(ks.getMine().key, 'asdf', 'asdf')
    print hexlify(s)
    print verify_response(ks.getMine().key, 'asdf', 'asdf', s)
