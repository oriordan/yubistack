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
from secretsharing import PlaintextToHexSecretSharer

# Older versions of PyCrypto don't skip pad/unpad, we only care about the
# PKCS#7 variants here.
try:
    from Crypto.Util.Padding import pad, unpad
except ImportError:

    def pad(data, block_size):
        """Pad a block of data to align with block_size using PKCS#7 padding."""
        return data + chr(len(data)) * ((block_size - len(data)) % block_size)

    def unpad(data, block_size):
        """Remove block padding from PKCS#7 padding."""
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
commands:
  secret                generate a new shared secret
  test-secret           reconstruct a shared secret from shares
  test <keydir>         encrypt & decrypt <rounds> number of keys

in order to start using the encrypter/decrypter, you have to set up a key
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

now you can split the secret used to protect 2.private using the secret
command:

  ~$ python yubistack/crypt.py secret

'''


class SHA2(object):
    """Wrapper for the SHA-256 hashing algorithm."""
    digest_size = 32

    def __init__(self, *args):
        if args and args[0] is object():
            self._hash = args[0].copy()
        else:
            self._hash = hashlib.new('sha256')

    def copy(self):
        """Make a (mutable) copy of the hash."""
        return SHA2(self._hash.copy())

    def digest(self, *args):
        """Calculate the hash digest."""
        return self._hash.digest(*args)

    def hexdigest(self, *args):
        """Calculate the hash hexdigest."""
        return self._hash.hexdigest(*args)

    def update(self, *args):
        """Update the hash."""
        return self._hash.update(*args)


SHA2.new = SHA2


class Crypter(object):
    """Crypter base class for doing encryption and decryption."""

    mask = '*.*'
    shares = 2

    def __init__(self, keydir):
        # Keydir path
        self.keydir = os.path.abspath(keydir)
        # Secret sharer
        self.sharer = PlaintextToHexSecretSharer()
        self._passphrase = None
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

        logging.info('Crypter krn=%d', self.krn)

    def cipher(self, krn=None):
        """Generate a cipher for the given key rotation number."""
        return PKCS1_OAEP.new(
            self.key[krn or self.krn],  # key
            SHA2,                       # digest
        )

    def decrypt(self, ciphertext, krn=None):
        """Decrypt a ciphertext."""
        return self.cipher(krn).decrypt(ciphertext)

    def encrypt(self, plaintext, krn=None):
        """Encrypt a plaintext."""
        return self.cipher(krn).encrypt(plaintext)

    def load_keyfile(self, keyfile):
        """Load a key file."""
        raise NotImplementedError('Implement me in subclass')


class PublicKey(Crypter):
    """Public key that can encrypt."""

    mask = '*.public'

    def decrypt(self, ciphertext, krn=None):
        raise NotImplementedError("Public key can only encrypt")

    def load_keyfile(self, keyfile):
        with open(keyfile) as handle:
            return RSA.importKey(handle.read())


class PrivateKey(Crypter):
    """Private key that can both encrypt and decrypt.

    The private key may be encrypted using 3DES-CBC or AES-128-CBC, if so, it
    is assumed that the decryption secret is split using Shamir's Shared Secret
    algorithm.
    """

    mask = '*.private'

    def load_keyfile(self, keyfile):
        with open(keyfile) as handle:
            keydata = handle.read()
            try:
                return RSA.importKey(keydata)
            except ValueError:
                return RSA.importKey(self.load_encrypted_keydata(keydata))

    def load_encrypted_keydata(self, keydata):
        """Load a key from encrypted keydata (in PEM format)."""
        lines = keydata.strip().replace(' ', '').splitlines()
        if not lines[1].startswith('Proc-Type:4,ENCRYPTED'):
            raise TypeError('Unsupported encryption')

        dek = lines[2].split(':')
        if len(dek) != 2 or dek[0] != 'DEK-Info':
            raise ValueError('PEM encryption method not supported')

        algo, salt = dek[1].split(',')
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
        """Return the loaded passphrase or request the shares to derive it.

        This prompts the user for shares of the shared secret.
        """
        if self._passphrase is None:
            shares = []
            for part in range(self.shares):
                while True:
                    share = raw_input('enter share [%d/%d]: ' % (part + 1, self.shares))
                    if share:
                        shares.append(share)
                        break

            self._passphrase = self.sharer.recover_secret(shares)

        return self._passphrase


def run():
    """Main entry point."""
    import argparse

    logging.basicConfig(
        format='%(asctime)s %(levelname)s %(module)s %(funcName)s: %(message)s',
        level=logging.DEBUG,
    )

    parser = argparse.ArgumentParser(
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = parser.add_argument_group('test args')
    group.add_argument('-r', '--rounds', type=int, default=100)
    group.add_argument('-k', '--krn', type=int, default=None)
    group.add_argument('--pub', default=False, action='store_true')
    group = parser.add_argument_group('secret args')
    group.add_argument(
        '-s', '--shares', type=int, default=25, help='shares (default: 25)')
    group.add_argument(
        '-p', '--parts', type=int, default=2, help='parts (default: 2)')
    parser.add_argument('command')
    parser.add_argument('args', nargs='*')
    args = parser.parse_args()

    if args.command == 'secret':
        sharer = PlaintextToHexSecretSharer()
        secret = ''
        while not secret:
            secret = getpass.getpass('Please enter a secret: ')

        shares = sharer.split_secret(secret, args.parts, args.shares)
        for share in shares:
            print(share)

    elif args.command == 'test-secret':
        sharer = PlaintextToHexSecretSharer()
        shares = []
        while True:
            share = raw_input('Share: ')
            if not share:
                break
            shares.append(share)

        print('Secret: ' + sharer.recover_secret(shares))

    elif args.command == 'test':
        if not args.args:
            parser.error('missing keydir')
            return 1

        if args.pub:
            crypter = PublicKey(args.args[0])
        else:
            crypter = PrivateKey(args.args[0])

        logger.info('running %d test rounds', args.rounds)
        for count in range(args.rounds):
            plaintext = os.urandom(16).encode('hex')
            print('encrypt', plaintext)
            ciphertext = crypter.encrypt(plaintext, krn=args.krn)
            print(base64.b64encode(ciphertext))
            if not args.pub:
                assert crypter.decrypt(ciphertext, krn=args.krn) == plaintext, \
                    'round %d failed' % (count,)
        logger.info('all good')

    else:
        parser.error('unknown command')
        return 1


if __name__ == '__main__':
    import sys
    sys.exit(run())
