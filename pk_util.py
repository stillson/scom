#!/usr/bin/env python

import uuid
from Crypto.PublicKey import RSA
from collections import namedtuple
import json
import os
from rdrand import Random
from binascii import unhexlify
from UserDict import DictMixin
from glob import glob

r = Random()
def randbytes(n):
    rv = '%x' % r.getrandbits(n*8)
    if len(rv) % 2 == 1: rv = '0' + rv
    return unhexlify(rv)

RawRSAKey  = namedtuple('RawRSAKey', 'id pem')
FullRSAKey = namedtuple('FullRSAKey', 'id key pem')

def newRSAKey(private=True):
    # uuid's aren't magic. just easy
    # you could use any unique id
    uu = str(uuid.uuid4())
    kid = str(uu[9:])
    key = RSA.generate(4096,randfunc=randbytes)
    if not private:
        key = key.publickey()
    full_key = FullRSAKey(kid, key, key.exportKey())
    return full_key

"""
=======
keyfile (json)

[<id> , <raw_pem> ]

store:
======

{ "mine" : [ <id>, <raw_pem> ],
  "store" : { <id1> : [ <id1>, <raw_pem2>],
              <id2> : [ <id2>, <raw_pem2>],
              ....
              <idn> : [ <idn>, <raw_pemn>]
            }
}
"""


class KeyStore(DictMixin):
    def __init__(self, store_file='.scom-keys'):
        self.mine = None
        self.store = {}
        self.store_file = store_file

    def loadStore(self):
        with open(self.store_file,'r') as f:
            json_in = json.load(f)

        self.mine = json_in['mine']
        mine_raw = RawRSAKey(*self.mine)
        self.mine = FullRSAKey(str(mine_raw.id), RSA.importKey(mine_raw.pem), mine_raw.pem)

        raw_store = json_in['store']

        new_store = {}
        for  k,v in raw_store.items():
            new_store[k] = FullRSAKey(str(v[0]), RSA.importKey(v[1]), v[1] )

        self.store = new_store

class BaseKeyStore(DictMixin):
    def __init__(self):
        self.mine = None
        self.store = {}

    def saveStore(self):
        pass

    def loadStore(self):
        pass

    def items(self):
        return self.store.items()

    def __getitem__(self, item):
        return self.store.get(item,None)

    def __setitem__(self, key, value):
        assert isinstance(value, FullRSAKey)
        self.store[key] = value

    def __delitem__(self, key):
        del self.store[key]

    def keys(self):
        return self.store.keys()

    def setMine(self, value):
        assert isinstance(value, FullRSAKey)
        self.mine = value

    def getMine(self):
        return self.mine

class KeyStore_SQL(DictMixin):
    # not writing this yet. just an idea
    pass

class KeyStore_Dir(BaseKeyStore):
    def __init__(self, store_dir='/etc/scom'):
        self.mine = None
        self.store = {}
        self.store_dir = store_dir

    def loadStore(self):
        mine = self.store_dir + '/scom_id'
        others = glob(self.store_dir + '/*.scom')

        def load_json_file(fname):
            with open(fname, 'r') as f:
                json_in = json.load(f)

            return FullRSAKey(str(json_in[0]), RSA.importKey(json_in[1]), json_in[1])

        self.mine = load_json_file(mine)

        for fname in others:
            k = load_json_file(fname)
            self.store[k.id] = k

    def saveStore(self):
        def save_json_file(self, key, name=None):
            if not name:
                name = self.store_dir
            with open(name, 'w') as f:
                json.dump([key.id, key.pem], f, indent=4)

        mine = self.store_dir + '/scom_id'
        save_json_file(self,self.mine, name=self.store_dir + '/scom_id' )

        for name in self.store.keys():
            save_json_file(self, self.store[name], self.store_dir + '/' + name + '.scom')

class KeyStore_JSON(BaseKeyStore):
    def __init__(self, store_file='.scom-keys'):
        self.mine = None
        self.store = {}
        self.store_file = store_file

    def loadStore(self):
        with open(self.store_file,'r') as f:
            json_in = json.load(f)

        self.mine = json_in['mine']
        mine_raw = RawRSAKey(*self.mine)
        self.mine = FullRSAKey(str(mine_raw.id), RSA.importKey(mine_raw.pem), mine_raw.pem)

        raw_store = json_in['store']

        new_store = {}
        for  k,v in raw_store.items():
            new_store[k] = FullRSAKey(str(v[0]), RSA.importKey(v[1]), v[1] )

        self.store = new_store

    def saveStore(self):
        def makeStorefile(self):
            f = open(self.store_file, 'w')
            f.write(' ')
            f.close()
            os.chmod(self.store_file, 0600)

        full_store = {}
        store = {}

        full_store['mine'] = (self.mine.id, self.mine.pem)
        full_store['store'] = store

        for k,v in self.store.items():
            store[k] = (v.id, v.pem)

        makeStorefile(self)

        with open(self.store_file, 'w') as f:
            json.dump(full_store, f, indent=4)


KeyStore = KeyStore_Dir

### Tests ###

if __name__ == '__main__':
    a = KeyStore()

    print 'mine'
    mine = newRSAKey()
    print 'other1'
    other1 = newRSAKey(False)
    print 'other2'
    other2 = newRSAKey(False)

    a.setMine(mine)
    a[other1.id] = other1
    a[other2.id] = other2

    a.saveStore()

    a.loadStore()

    print a.getMine()

    print

    for k,v in a.items():
        print k
        print v
