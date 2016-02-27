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

    Usage:
    >>> st = SoftToken('tetetetetecc', '8792ebfe26cc', 'ecde18dbe76fbd0c33330f1c354871db')
    >>> st.counter = 19
    >>> st.timestamp_low = 49320
    >>> st.timestamp_high = 0
    >>> st.session_use = 16
    >>> for i in range(0, 5):
    ...     st.otp()
    ...
    'tetetetetecccrgkcdjhtfebjvvvufuuccvetbinrhuv'
    'teteteteteccvtjfbfdrictrndbeubdtccbhhdblinvb'
    'teteteteteccfjtjkfhrnbcrgjnrcvrktffnirdkhukn'
    'teteteteteccfjjkiivgrcnvbkgiffckkglentvtekfb'
    'teteteteteccvhfftjitevuvuehhbvcktcgndnuiblbr'
    >>>
    """

    def __init__(self, public_id, internalname, aeskey):
        self.public_id = public_id
        self.internalname = internalname
        self.aeskey = aeskey
        self.counter = 0
        self.timestamp_low = 0
        self.timestamp_high = 0
        self.session_use = 0

    def otp(self):
        """ Generate OTP token """
        _random = '%.4x' % randint(0, 65536)
        counter_hex = '%.4x' % self.counter
        low_hex = '%.4x' % self.timestamp_low
        high_hex = '%.2x' % self.timestamp_high
        use_hex = '%.2x' % self.session_use
        self.session_use += 1
        token = (self.internalname +
                 counter_hex[2:4] +
                 counter_hex[0:2] +
                 low_hex[2:4] +
                 low_hex[0:2] +
                 high_hex +
                 use_hex +
                 _random[2:4] +
                 _random[0:2])
        crc_hex = '%.4x' % (~calculate_crc(token) & 0xffff)
        token += crc_hex[2:4] + crc_hex[0:2]
        return self.public_id + aes128ecb_encrypt(self.aeskey, token)

def main():
    """ Main program """
    token = SoftToken('tetetetetecc', '8792ebfe26cc', 'ecde18dbe76fbd0c33330f1c354871db')
    token.counter = 19
    token.timestamp_low = 49320
    token.timestamp_high = 0
    token.session_use = 16
    for _ in range(0, 5):
        print(token.otp())

if __name__ == '__main__':
    main()

