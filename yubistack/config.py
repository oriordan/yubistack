"""
yubistack.config
~~~~~~~~~~~~~~~~

Settings file parser module
"""

__all__ = [
    'settings',
]

import imp
import os
import logging

# CONSTANTS
TS_SEC = 0.128 # 8Hz timer of the HW token
TS_REL_TOLERANCE = 0.3
TOKEN_LEN = 32 # Lengh of Yubikey OTP tokens
OTP_MAX_LEN = 48 # TOKEN_LEN plus public identity of 0..16

SETTINGS_FILE = os.getenv('YUBISTACK_SETTINGS', '/etc/yubistack.conf')
DEFAULT_CRYPT_CONTEXT = {
    'schemes': ['sha256_crypt'],
    'deprecated': [],
    'default': 'sha256_crypt',
    'yhsm_pbkdf2_sha1__key_handle': 1,
    'all__vary_rounds': 0.1,
    'sha256_crypt__min_rounds': 80000,
    'admin__sha256_crypt__min_rounds': 160000
}
VALUES = [
    ('DATABASES', {}),
    ('USE_HSM', False),
    ('USE_NATIVE_YKVAL', False),
    ('USE_NATIVE_YKKSM', False),
    ('CRYPT_CONTEXT', DEFAULT_CRYPT_CONTEXT),
    ('YKVAL_CLIENT_ID', None),
    ('YKVAL_CLIENT_SECRET', ''),
    ('YKVAL_SERVERS', []),
    ('YKKSM_KEYDIR', ''),
    ('YKKSM_SERVERS', []),
    ('YKKSM_KEYDIR', False),
    ('LOGLEVEL', 'INFO'),
    ('LOGFILE', '/tmp/yubistack.log'),
    ('SYNC_SERVERS', []),
    ('SYNC_LEVEL', 100),
    ('SYNC_POOL', []),
    ('SYNC_TIMEOUT', 3),
    ('SYSLOG_WSGI_AUTH', True),
    ('TS_ABS_TOLERANCE', 0),
]

def parse(conf):
    """ Parse settings file parameters into a dict """
    _settings = {}
    for conf_key, default_value in VALUES:
        _settings[conf_key] = getattr(conf, conf_key, default_value)
    return _settings

if os.path.isfile(SETTINGS_FILE):
    user_settings = imp.load_source('user_settings', SETTINGS_FILE)
    settings = parse(user_settings)
else:
    settings = dict(VALUES)

loglevel = getattr(logging, settings['LOGLEVEL'], logging.INFO)
logging.basicConfig(format='%(asctime)s %(levelname)s %(module)s %(funcName)s: %(message)s',
                    level=loglevel, filename=settings['LOGFILE'])
