"""

Yubikey Python Authentication Stack
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Components:
    ykauth: Authentication Module
    ykval: Validation Module
    ykksm: Key Storage Module

Examples:
>>> from yubistack import Client
>>> c = Client()
>>> c.authenticate('joe', 'secret', 'ccccccbcgujhingjrdejhgfnuetrgigvejhhgbkugded')
False
>>>
>>> from yubistack import Validator
>>> v = Validator()
>>> v.verify(1, 'ccccccbcgujhingjrdejhgfnuetrgigvejhhgbkugded')
{'otp': 'ccccccbcgujhingjrdejhgfnuetrgigvejhhgbkugded', 'time': '2015-04-14T20:07:20Z5261', \
 'nonce': None, 'status': 'OK', 'sl': None, 'signature': 'h0P2wfJUqHQFuRpG4n1Kvk3KacE='}
>>>
>>> from yubistack import Decryptor
>>> d = Decryptor()
>>> d.decrypt('ccccccbcgujhingjrdejhgfnuetrgigvejhhgbkugded')
{'counter': '0235', 'low':' 21c4', 'high': 'b2', 'use':'42'}
"""

__version__ = '0.5.5'
__all__ = [
    'settings',
    'Client',
    'Decryptor',
    'Sync',
    'Validator',
]

import imp
import os
import logging

from .config import settings
from .ykauth import Client
from .ykksm import Decryptor
from .yksync import Sync
from .ykval import Validator
