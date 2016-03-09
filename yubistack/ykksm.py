"""
yubistack.ykksm
~~~~~~~~~~~~~~~

Yubikey Key Storage Manager - Decryption module
"""

import base64
import logging
import re

from Crypto.Random import atfork

from .config import settings
from .crypt import PrivateKey
from .db import DBHandler
from .exceptions import YKKSMError
from .utils import (
    aes128ecb_decrypt,
    check_crc,
)

logger = logging.getLogger(__name__)
OTP_REGEX = re.compile(r'^(?P<yk_id>[cbdefghijklnrtuv]{0,16})(?P<modhex>[cbdefghijklnrtuv]{32})$')


CRYPTER = None
if settings.get('YKKSM_KEYDIR') and PrivateKey:
    CRYPTER = PrivateKey(settings['YKKSM_KEYDIR'])

class DecryptorDBH(DBHandler):
    """
    Transparently decrypt RSA encrypted aeskeys
    """
    def get_key_and_internalname(self, public_id):
        data = DBHandler.get_key_and_internalname(self, public_id)
        if data:
            try:
                # AES keys are 16 bytes (hex)
                if len(data['aeskey']) != 32:
                    raise ValueError
                else:
                    int(data['aeskey'], 16)
            except ValueError:
                # Re-initialize RNG to deal with forks in uwsgi
                atfork()
                # Encrypted ciphertext with base64 encoding
                ciphertext = base64.b64decode(data['aeskey'])
                data['aeskey'] = CRYPTER.decrypt(ciphertext)

            return data


class Decryptor:
    """ Object to decrypt an OTP """
    def __init__(self, db='ykksm'):
        if settings.get('YKKSM_KEYDIR'):
            self.db = DecryptorDBH(db=db)
        else:
            self.db = DBHandler(db=db)

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
            raise YKKSMError('BAD_OTP')
        return match.groups()

    def _get_key_and_internalname(self, public_id):
        """
        Get user's AES key from DB

        Output: (aeskey, internalname)

        NOTE: Consider using a Yubikey HSM stick instead of ykksm
        """
        data = self.db.get_key_and_internalname(public_id)
        if not data:
            raise YKKSMError('UNKNOWN_TOKEN')
        logger.debug('Found user: ID: %s, INTERNALNAME: %s',
                     public_id, data['internalname'])
        return (data['aeskey'], data['internalname'])

    def decrypt(self, otp):
        """ Decrypt OTP """
        if not otp:
            logger.error('Missing OTP')
            raise YKKSMError('MISSING_OTP')
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
            raise YKKSMError('CORRUPT_OTP')
        if not check_crc(plaintext):
            logger.error('CRC Error: %s: %s', otp, plaintext)
            raise YKKSMError('CORRUPT_OTP')
        # Construct output
        output = {
            'counter': plaintext[14:16] + plaintext[12:14],
            'low': plaintext[18:20] + plaintext[16:18],
            'high': plaintext[20:22],
            'use': plaintext[22:24]
        }
        logger.debug('SUCCESS OTP %s PT %s %s', otp, plaintext, output)
        return output
