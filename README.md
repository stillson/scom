# scom
simple secure communications in python

After years of hearing people say "Don't write your own crypto code, ever. You
aren't good enough", I realized "Screw Them. I actually am good enough"

So, I wrote this.

RSA signed diffie helman for keys
256 AES with SHA256 hmac for symmetric keys
Overly strong, but could be changed if needed.

Different key pairs in each direction.
DH prime and generator are random, and regenerated at configurable intervals,
to deal with problems of using a known generator/prime to calculated possible
discrete logs ahead of time.

The signing is pkcs1.5 with sha256 and the possibility of using sha256-hmac if there
are collisions found in sha256.

Symmetric encryption uses a running hash to prevent replay.

More about how to use it later.

BSD 2 clause license
