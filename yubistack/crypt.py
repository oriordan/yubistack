from __future__ import print_function

import base64
import getpass
import glob
import hashlib
import logging
import os
import re

from Crypto.Cipher import DES, DES3, AES, PKCS1_OAEP
from Crypto.Hash import MD5
from Crypto.Protocol.KDF import PBKDF1
from Crypto.PublicKey import RSA
from Crypto.Util import asn1

# Older versions of PyCrypto don't skip pad/unpad, we only care about the
# PKCS#7 variants here.
try:
    from Crypto.Util.Padding import pad, unpad
except ImportError:

    def pad(data, block_size):
        return data + chr(len(data)) * ((block_size - len(data)) % block_size)

    def unpad(data, block_size):
        if len(data) % block_size:
            raise ValueError('Input data is not padded')
        
        pad_len = ord(data[-1])
        if pad_len < 1 or pad_len > min(block_size, len(data)):
            raise ValueError('Incorrect padding')

        elif data[-pad_len:] != chr(pad_len) * pad_len:
            raise ValueError('PKCS#7 padding incorrect')

        else:
            return data[:-pad_len]


logger = logging.getLogger(__name__)


EPILOG = '''
In order to start using the encrypter/decrypter, you have to set up a key
directory first:

  ~$ mkdir keys
  keys$ # for --krn=1:
  keys$ openssl genrsa -out 1.private
  ...
  keys$ # for --krn=2:
  keys$ openssl genrsa -out 2.private -aes128
  ...
  keys$ openssl rsa -in 1.private -pubout > 1.public
  keys$ openssl rsa -in 2.private -pubout > 2.public

'''


class SHA2(object):
    digest_size = 32

    def __init__(self, *args):
        if args and args[0] is object():
            self._h = args[0].copy()
        else:
            self._h = hashlib.new('sha256')

    def copy(self):
        return SHA2(self._h.copy())

    def digest(self, *args):
        return self._h.digest(*args)

    def hexdigest(self, *args):
        return self._h.hexdigest(*args)

    def update(self, *args):
        return self._h.update(*args)


SHA2.new = SHA2


class Crypter(object):
    mask = '*.*'

    def __init__(self, keydir):
        # Keydir path
        self.keydir = os.path.abspath(keydir)
        # Our key rotation number
        self.krn = None
        self.key = {}
        
        # Load keyfile with highest krn from disk
        keyfiles = os.path.join(self.keydir, self.mask)
        for path in sorted(glob.glob(keyfiles)):
            part = os.path.basename(path).split('.')
            if not part[-2].isdigit():
                continue

            krn = int(part[-2])
            if krn > self.krn:
                self.krn = krn

            self.key[krn] = self.load_keyfile(path)

        if not self.krn:
            raise ValueError('No key was loaded')

        logging.info('Crypter krn=%d' % (self.krn,))

    def cipher(self, krn=None):
        return PKCS1_OAEP.new(
            self.key[krn or self.krn],  # key
            SHA2,                       # digest
        )

    def decrypt(self, ciphertext, krn=None):
        return self.cipher(krn).decrypt(ciphertext)

    def encrypt(self, plaintext, krn=None):
        return self.cipher(krn).encrypt(plaintext)


class PublicKey(Crypter):
    mask = '*.public'

    def load_keyfile(self, keyfile):
        with open(keyfile) as fp:
            return RSA.importKey(fp.read())


class PrivateKey(Crypter):
    mask = '*.private'

    def load_keyfile(self, keyfile):
        with open(keyfile) as fp:
            keydata = fp.read()
            try:
                return RSA.importKey(keydata)
            except ValueError:
                return RSA.importKey(self.load_encrypted_keydata(keydata))

    def load_encrypted_keydata(self, keydata):
        lines = keydata.strip().replace(' ', '').splitlines()
        if not lines[1].startswith('Proc-Type:4,ENCRYPTED'):
            raise TypeError('Unsupported encryption')

        DEK = lines[2].split(':')
        if len(DEK) != 2 or DEK[0] != 'DEK-Info':
            raise ValueError('PEM encryption method not supported')

        algo, salt = DEK[1].split(',')
        salt = salt.decode('hex')

        if algo == 'DES-CBC':
            key = PBKDF1(self.passphrase, salt, 8, 1, MD5)
            obj = DES.new(key, DES.MODE_CBC, salt)

        elif algo == 'DES-EDE3-CBC':
            key = PBKDF1(self.passphrase, salt, 16, 1, MD5)
            key+= PBKDF1(key + passphrase, salt, 8, 1, MD5)
            obj = DES3.new(key, DES3.MOE_CBC, salt)

        elif algo == 'AES-128-CBC':
            key = PBKDF1(self.passphrase, salt[:8], 16, 1, MD5)
            obj = AES.new(key, AES.MODE_CBC, salt)

        else:
            raise TypeError('%s: cipher not supported' % (algo,))

        lines = lines[3:-1]
        data = ''.join(lines).decode('base64')
        return unpad(obj.decrypt(data), obj.block_size)

    @property
    def passphrase(self):
        if not hasattr(self, '_passphrase'):
            self._passphrase = getpass.getpass('Private key passphrase: ')
        return self._passphrase



def run():
    import argparse

    logging.basicConfig(
        format='%(asctime)s %(levelname)s %(module)s %(funcName)s: %(message)s',
        level=logging.DEBUG,
    )

    parser = argparse.ArgumentParser(
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('-r', '--rounds', type=int, default=100)
    parser.add_argument('-k', '--krn', type=int, default=None)
    parser.add_argument('--pub', default=False, action='store_true')
    parser.add_argument('keydir')
    args = parser.parse_args()

    if args.pub:
        crypter = PublicKey(args.keydir)
    else:
        crypter = PrivateKey(args.keydir)

    logger.info('running %d test rounds' % (args.rounds,))
    for r in range(args.rounds):
        p = os.urandom(16).encode('hex')
        print('encrypt', p, len(p))
        c = crypter.encrypt(p, krn=args.krn)
        print(base64.b64encode(c))
        if not args.pub:
            assert crypter.decrypt(c, krn=args.krn) == p, 'round %d failed' % (r,)
    logger.info('all good')


if __name__ == '__main__':
    import sys
    sys.exit(run())
