"""
yubistack.softtoken
~~~~~~~~~~~~~~~~~~~

Generating OTP with code o/
"""

from random import randint

from .utils import (
    calculate_crc,
    aes128ecb_encrypt,
)

class SoftToken:
    """
    SoftToken generator class
    """

    def __init__(self, public_id):
        self.public_id = public_id
        self.counter = 0
        self.timestamp_low = 0
        self.timestamp_high = 0
        self.session_use = 0

    def generate_otp(self):
        """ Generate OTP token for `public_id` """
        counter_hex = '%.4x' % self.counter
        low_hex = '%.4x' % self.timestamp_low
        high_hex = '%.4x' % self.timestamp_high
        use_hex = '%x' % self.session_use
        otp = (self.public_id +
               counter_hex[2:4] + counter_hex[0:2] +
               low_hex[2:4] + low_hex[0:2] +
               high_hex +
               use_hex)
        self.session_use += 1
        return otp

def otp(aeskey, internalname, counter, low, high, use):
    """ Generate OTP token """
    random = '%.4x' % randint(0, 65536)
    otp = (internalname +
           counter[2:4] + counter[0:2] +
           low[2:4] + low[0:2] +
           high +
           use + 
           random[2:4] + random[0:2])
    crc_hex = '%.4x' % (~calculate_crc(otp) & 0xffff)
    otp += crc_hex[2:4] + crc_hex[0:2]
    return aes128ecb_encrypt(aeskey, otp)
