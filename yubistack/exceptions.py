"""

yubistack.exceptions
~~~~~~~~~~~~~~~~~~~~

List all custom exceptions here
"""

STATUS_CODES = {
    # YKAuth
    'BAD_PASSWORD': 'Invalid password',
    'DISABLED_TOKEN': 'Token is disabled',
    'UNKNOWN_USER': 'Unknown user',
    'INVALID_TOKEN': 'Token is not associated with user',
    # YKVal
    'BACKEND_ERROR': 'Backend error',
    'BAD_OTP': 'Invalid OTP',
    'BAD_SIGNATURE': 'The HMAC signature verification failed',
    'DELAYED_OTP': 'Expired OTP',
    'INVALID_PARAMETER': 'The request has invalid parameter',
    'MISSING_PARAMETER': 'The request missing parameter',
    'NO_SUCH_CLIENT': 'The request id does not exist',
    'NOT_ENOUGH_ANSWERS': 'Server could not get requested number of syncs before timeout',
    'OPERATION_NOT_ALLOWED': 'The request is now allowed',
    'REPLAYED_OTP': 'Replayed OTP',
    'REPLAYED_REQUEST': 'Server has seen the OTP/Nonce combination before',
    # YKKSM
    'CORRUPT_OTP': 'Corrupt OTP',
    'MISSING_OTP': 'No OTP provided',
    'UNKNOWN_TOKEN': 'Unknown yubikey',
}

class YubistackError(Exception):
    """ Yubistack Exception """
    NAME = 'Yubistack error'
    def __init__(self, *args):
        super(YubistackError, self).__init__(*args)
        self.error_code = self.args[0]

    def __str__(self):
        message = STATUS_CODES[self.error_code]
        if len(self.args) == 2:
            message += ': %s' % self.args[1]
        return message

class YKAuthError(YubistackError):
    """ Error returned by the Client class """
    NAME = 'Authentication error'

class YKValError(YubistackError):
    """ Error returned by the Validator class """
    NAME = 'Validation error'

class YKSyncError(YubistackError):
    """ Error returned by the Sync class """
    NAME = 'Sync error'

class YKKSMError(YubistackError):
    """ Error returned by the Decryptor class """
    NAME = 'Decryption error'
