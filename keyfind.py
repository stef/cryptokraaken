#!/usr/bin/env python
# composes regexps and locates them in supplied image.
# use kraakengrep for more performant scanning.
# exponents in private keys only match with 65537, todo: expand with
# other fermat primes: {3, 5, 17, 257} at least

import struct, re, sys, mmap, itertools, hashlib

# common functions for ssl and pgp
def quote(frag):
    return ''.join("[%c]" % x if x in '({[.+*?\\' else x for x in frag)

def _tobin(num,bytes=0):
    res = []
    if num==0:
        res=['\0']
    while num:
        res.append(chr(num&0xff))
        num>>=8
    res.reverse()
    if bytes and len(res)<bytes:
        res =['\0' * (bytes-len(res))] +res
    return res

def tobin(num,bytes=0):
    return quote(''.join(_tobin(num,bytes)))

def suffixtree(exp): # not really a suffixtree, more like a suffix list
    res = {}
    for item in exp:
        if not item[0] in res:
            res[item[0]]=[item[1:]] if len(item)>2 else [item[1]]
        else:
            res[item[0]].append(item[1:] if len(item)>2 else item[1])
    return res

def compress(exp): # takes pairs, returns a simplified regex
    res = []
    tree = suffixtree(exp)
    for k, v in tree.items():
        if set(isinstance(i,str) for i in v) == set([True]):
            if len(v)>1:
                res.append("%s[%s]" % (k, ''.join(v)))
            else:
                res.append("%s%s" % (k, v[0]))
    return '|'.join(res)

# ssl related functions

def pkcs1size(size):
    if size<128:
        return "[%s]" % chr(size)
    for fsize in xrange(1,6):
        if size>=(1<<(8*fsize)):
            continue
        return  '%c%s' % (0x80+fsize,tobin(size,fsize))

def number(val=None, psize=None, range=1):
    if val!=None:
        val=tobin(val)
        psize=len(val)
        return '\x02%s%s' % (pkcs1size(psize), val)
    elif psize:
        return "\x02(?:%s)" % '|'.join('%s.{%d}' % (pkcs1size(psize+i), psize+i) for i in xrange(-range,range+1))

def rsaparam(psize):
    f=number(psize=psize)
    h="(?:%s){5}" % number(psize=psize/2)
    return ''.join(f + number(65537) + f + h) # + h + h + h + h)

def pkcs1rsa(): # pkcs8 has pkcs1 inside
    # finds DER encoded pkcs#1 RSA keys with exponent 65537 and
    # [1024,2048,3072,4096] bit keysize
    return '\x30(?:%s)%s(?:%s)' % ('|'.join(['%c.{%s}' % (chr(0x80+x),x) # todo calculate more specific sizes
                                             for x in xrange(2,6)]),
                                   number(0),
                                   '|'.join([rsaparam(x)
                                             for x in [512,384,256,128,64]]))
# pgp related functions

def choice(opts):
    return '[%s]' % ''.join(chr(x) for x in opts)

def tochoice(opts):
    return "(?:%s)" % compress([_tobin(x) for x in opts])

def size(size, range=2):
    return "(?:%s)" % compress([tobin(size+i,2) for i in xrange(-range,1)])

#\x95..\x04.{4}[\x01\x02](?:size)(?:[0,1,2,3,4,7,8,9,10]|[254,255][1,2,3,4,7,8,9,10][0,1,3][1,2,3,8,9,10,11]

# secret (sub) key (5|7) old, 2 byte size 0x95|0x97
# .. length
# version 0x04
# .... creation date
# [\x01\x02] pub key type (rsa sign+enc 1, rsa encrypt only 2)
# size in bits, .... (size+7 //8), n
# size in bits (17) \x01\x00\x01 , exponent
# 0,C, [254, 255]C[0,1,3,101]H - s2k
#C = [1,2,3,4,7,8,9,10]
#H = [1,2,3,8,9,10,11]

def pktsize(ksize=3072):
    base = (1 +                              # version
            4 +                              # creation date
            1 +                              # pub alg
            ((ksize+7) // 8) + 2 +           # n
            5 +                              # exponent
            ((ksize+7) // 8) + 2 +           # d
            (((((ksize/2)+7) // 8) +2)*3) +  # p, q, u
            1)                               # s2k
    kdf = [(base +     # simple
            1 +               # symmetric algo
            1 +               # simple s2k // 0x00
            1),               # hash algo
           (base +     # salted
            1 +               # symmetric algo
            1 +               # Salted S2K // 0x01
            1 +               # hash algo
            8),               # salt
           (base +     # gnupg 101
            6),               # gnu + simple?
           (base +     # interated and salted
            1 +               # symmetric algo
            1 +               # Iterated and Salted S2K // 0x03
            1 +               # hash algo
            8 +               # salt
            1)]               # iterations
    blocksizes = [16,32]
    checkhash = [2,20]

    return [base+2]+[s+c+k for s in kdf for c in checkhash for k in blocksizes]

def pgprsa():
    sizeopts = "(?:%s)" % '|'.join('%s\x04.{4}%s%s.{%s}' % (tochoice(pktsize(psize)),
                                                                choice([1,2]),
                                                                size(psize),
                                                                (psize+7) // 8)
                               for psize in [1024, 2048, 3072, 4096, 8192])

    return '[\x95\x97\x9d]%s\x00\x11\x01\x00\x01(?:%s|%s%s%s%s)' % (
        sizeopts,
        choice([0,1,2,3,4,7,8,9,10]), # cipher
        choice([254,255]),
        choice([1,2,3,4,7,8,9,10]), # cipher
        choice([0,1,3,101]),     # s2k
        choice([1,2,3,8,9,10,11]))

def pgpsym():
    #     - A one-octet version number.  The only currently defined version
    #       is 4.
    #
    #     - A one-octet number describing the symmetric algorithm used.
    #
    #     - A string-to-key (S2K) specifier, length as defined above.
    #
    #     - Optionally, the encrypted session key itself, which is decrypted
    #       with the string-to-key object.

    h = choice([1,2,3,8,9,10,11])
    c = choice([1,2,3,4,7,8,9,10])
    s2k = '(?:\x01%s.{8}|\x03%s.{9})' % (h,h)
    return '(?:\x8c[\x0d\x0c]\x04%s%s)+[\xd2\xc9]' % (c, s2k)

def pgpasym():
    #Old: Public-Key Encrypted Session Key Packet(tag 1)(524 bytes)
    #    New version(3)
    #    Key ID - 0x0123456789abcdef
    #    Pub alg - RSA Encrypt or Sign(pub 1)
    #    RSA m^e mod n(4091 bits) - ...
    #            -> m = sym alg(1 byte) + checksum(2 bytes) + PKCS-1 block type 02

    p = choice([1,2])
    return "(?:%s)+\xd2(?:.|..|.....)\x01" % "|".join(
        ["%c%s\x03.{8}%s(?:%s).{%s}" % ('\x84' if len(tobin(((size+7) // 8)+12))==1 else '\x85',
                                    tobin(((size+7) // 8)+12),
                                    p,
                                    compress([_tobin(size+i) for i in xrange(-7,1)]),
                                    ((size+7) // 8))
         for size in [1024,2048,3072,4096,8192]
         ])

def pgparmor():
    return ''.join(['-----BEGIN PGP MESSAGE-----\x0a\x0d?',  # header
                    '(?:(?:[^\x0a]+\x0a\x0d?)+\x0a\x0d?)?',  # version, comment
                    '(?:[A-Za-z0-9+/]+\s*\x0a\x0d?)+',       # base64 data
                                                             # last data line, can haz = or ==
                    '(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\s*\x0a\x0d?',
                                                             # optional last line, can haz =[[:base64:]]{4}
                                                             # - if there would be a base64 char class
                    '(?:=[A-Za-z0-9+/]{4}\s*\x0a\x0d?)?',
                    '-----END PGP MESSAGE-----'])

knownkeys = { '6703d04c2c33f79cb27bf73072c91941': 'openssl speed key 4096',
              '460ff240ad1b84d9a6fa21db4cf00b0b': 'openssl speed key 2048',
              'ad839da2337b6806979ac3ca8d5c5067': 'openssl speed key 1024',
              }

regexps = {'ssl': pkcs1rsa(),
           'pgp': pgprsa(),
           'pgpsym': pgpsym(),
           'pgpasym': pgpasym(),
           'pgparm': pgparmor(),
           }
if __name__ == "__main__":
    debug = False
    if debug: import traceback

    exp = []
    for k, v in regexps.items():
        if k in sys.argv:
            exp.append("(?P<%s>%s)" % (k, v))
            del sys.argv[sys.argv.index(k)]
    if len(exp)>0:
        exp = '|'.join(exp)
    else:
        exp = "(?P<ssl>%s)|(?P<pgp>%s)|(?P<pgpsym>%s)|(?P<pgpasym>%s)|(?P<pgparm>%s)" % (pkcs1rsa(), pgprsa(), pgpsym(), pgpasym(), pgparmor())

    if debug:
        print '\n\n'.join(repr(x) for x in (pkcs1rsa(), pgprsa(), pgpsym(), pgpasym(), pgparmor()))
        print repr(exp)
        sys.exit()

    exp = re.compile(exp, re.S)
    stats = {'pgp': 0,
             'pgpsym': 0,
             'pgpasym': 0,
             'pgparm': 0,
             'ssl': 0}
    with open(sys.argv[1],'rb') as fd:
        mm = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_READ)
        m = exp.search(mm)
        if not m:
            print "not found"
            sys.exit(1)
        while m:
            type=[]
            for x in ['pgp', 'pgpsym', 'pgpasym', 'pgparm', 'ssl'] :
                try:
                    if not m.group(x): continue
                except IndexError:
                    continue
                type.append(x)
            if len(type)>1:
                print "wtf:", type
                sys.exit(1)
            type=type[0]
            stats[type]+=1
            if type in ['pgp','pgpsym','pgpasym']:
                if (ord(m.group()[0]) & 0xc0) == 0xc0:
                    print 'meh unimplemented new pgp pkt'
                elif ord(m.group()[0]) & 0x80: # parse old style pgp size
                    if (ord(m.group()[0]) & 0x3) == 0:
                        size = ord(m.group()[1]) + 3
                    elif (ord(m.group()[0]) & 0x3) == 1:
                        size = struct.unpack('>H', m.group()[1:3])[0] + 3
                    else:
                        print 'meh unsupported size type', mm[m.start()] & 0x3
                else:
                    print 'meh first byte of pgp bad', hex(ord(m.group()[0]))
                    sys.exit(1)
                print '###', {'pgp': 'pgp key',
                              'pgpsym': 'pgp symmetric encrypted',
                              'pgpasym': 'pgp public-key encrypted'}[type],
            elif type == 'pgparm':
                size = 0
                print '### pgp ascii armored message',
            elif type == 'ssl':
                size = struct.unpack('>H', m.group('ssl')[2:4])[0]
                print '### ssl key',
            else:
                print '! pgp xor ssl'
                size = None

            print m.start(), size,
            if type in ['pgp','ssl']:
                fp=hashlib.md5(m.group()).hexdigest()
                if fp in knownkeys:
                     print knownkeys[fp]
                else:
                     print fp
            else:
                print
            if not size:
                if type == 'pgparm':
                    print m.group()
                else:
                    print repr(m.group())
            else:
                print repr(mm[m.start():m.start()+size])
            print
            m = exp.search(mm, m.end()+1)
        if sum(stats.values()) == 0:
            print "nothing found"
        else:
            print 'stats'
            print '\n'.join('%s %4d' % (k, v) for k,v in stats.items())
