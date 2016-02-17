"""
yubistack.ykksm
~~~~~~~~~~~~~~~

Yubikey Key Storage Manager - Decryption module
"""

import logging
import re

from .config import settings
from .db import DBHandler
from .utils import (
    aes128ecb_decrypt,
    check_crc,
)

logger = logging.getLogger(__name__)
OTP_REGEX = re.compile(r'^(?P<yk_id>[cbdefghijklnrtuv]{0,16})(?P<modhex>[cbdefghijklnrtuv]{32})$')

try:
    from .crypt import PrivateKey
except ImportError:
    PrivateKey = None
    logger.exception('could not load crypto.PrivateKey')


CRYPTER = None
if settings.get('YKKSM_KEYDIR') and PrivateKey:
    CRYPTER = PrivateKey(settings['YKKSM_KEYDIR'])


class YKKSMError(Exception):
    """ Errors returned by the application """
    pass

class DBH(DBHandler):
    """
    Extending the generic DBHandler class with the required queries
    """

    def get_key_and_internalname(self, public_id):
        """
        Read token's AESkey and internalname for OTP decryption
        """
        query = """SELECT aeskey,
                          internalname
                     FROM yubikeys
                    WHERE ACTIVE = 1
                      AND publicname = %s"""
        self._execute(query, (public_id,))
        return self._dictfetchone()


class DecryptorDBH(DBH):
    """
    Transparently decrypt RSA encrypted aeskeys
    """
    def get_key_and_internalname(self, public_id):
        data = DBH.get_key_and_internalname(self, public_id)
        if data:
            try:
                # AES keys are 16 bytes (hex)
                if len(data['aeskey']) != 32:
                    raise ValueError
                else:
                    int(data['aeskey'], 16)
            except ValueError:
                # Encrypted ciphertext with base64 encoding
                ciphertext = data['aeskey'].decode('base64')
                data['aeskey'] = CRYPTER.decrypt(ciphertext)

            return data


class Decryptor(object):
    """ Object to decrypt an OTP """
    def __init__(self, db='ykksm'):
        if settings.get('YKKSM_KEYDIR'):
            self.db = DecryptorDBH(db=db)
        else:
            self.db = DBH(db=db)

    def _parse_otp(self, otp):
        """
        Parse Yubikey OTP and return (public_id, modhex)

        Example:
        >>> d._parse_otp('ccccccbcgujhingjrdejhgfnuetrgigvejhhgbkugded')
        ('ccccccbcgujh', 'ingjrdejhgfnuetrgigvejhhgbkugded')
        """
        match = re.match(OTP_REGEX, otp)
        if not match:
            logger.error('Invalid OTP format: %s', otp)
            raise YKKSMError('ERR Invalid OTP format')
        return match.groups()

    def _get_key_and_internalname(self, public_id):
        """
        Get user's AES key from DB

        Output: (aeskey, internalname)

        NOTE: Consider using a Yubikey HSM stick instead of ykksm
        """
        try:
            data = self.db.get_key_and_internalname(public_id)
        except Exception as err:
            logger.exception('Database error: %s', err)
            raise
        if not data:
            raise YKKSMError('ERR Unknown yubikey')
        logger.debug('Found user: ID: %s, INTERNALNAME: %s', public_id, data['internalname'])
        return (data['aeskey'], data['internalname'])

    def decrypt(self, otp):
        """ Decrypt OTP """
        if not otp:
            logger.error('No OTP provided')
            raise YKKSMError('ERR No OTP provided')
        # Get public_id, modhex, key and internalname
        public_id, modhex = self._parse_otp(otp)
        aeskey, internalname = self._get_key_and_internalname(public_id)
        # Get plaintext from key + modhexed cipher
        plaintext = aes128ecb_decrypt(aeskey, modhex)
        plaintext = plaintext.decode()
        # Check for plaintext corruption
        if plaintext[:12] != internalname:
            logger.error('UID Error: %s %s: %s vs %s',
                         otp, plaintext, plaintext[:12], internalname)
            raise YKKSMError('ERR Corrupt OTP')
        if not check_crc(plaintext):
            logger.error('CRC Error: %s: %s', otp, plaintext)
            raise YKKSMError('ERR Corrupt OTP')
        # Construct output
        output = {
            'counter': plaintext[14:16] + plaintext[12:14],
            'low': plaintext[18:20] + plaintext[16:18],
            'high': plaintext[20:22],
            'use': plaintext[22:24]
        }
        logger.info('SUCCESS OTP %s PT %s %s', otp, plaintext, output)
        return output
