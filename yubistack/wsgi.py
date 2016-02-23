"""
yubistack.wsgi
~~~~~~~~~~~~~~

WSGI wrappers around the yubistack functions
to support backward compatibility.
"""

import logging
import re

from yubistack.config import settings
from yubistack.utils import parse_querystring, wsgi_response
from yubistack.ykauth import YKAuthError, Client
from yubistack.ykksm import YKKSMError, Decryptor
from yubistack.ykval import (
    YKSyncError,
    YKValError,
    Sync,
    Verifyer,
)

logger = logging.getLogger(__name__)

URI_REGEX = re.compile(r"""
    ^/?                     # Leading slash might not be present
    (                       # Intersection: yubiauth and yubikey-val + yubikey-ksm differences
        wsapi(/\d+\.\d+)?   # YKVal and YKKsm uses wsapi prefix + protocol version
      | yubiauth/client     # Yubiclient authentication URI
    )
    /
    (?P<resource>           # The resource should map to a function name
        (
            decrypt
          | verify
          | sync
          | resync
          | authenticate
        )
    )
    /?                      # Trailing clash might not be present
""", re.VERBOSE)

def authenticate(environ, start_response):
    """
    Handle authentications
    """
    REQUIRED_PARAMS = ['username', 'password', 'otp']
    username = '?'
    try:
        # Parse POST request
        try:
            request_body_size = int(environ.get('CONTENT_LENGTH', 0))
        except ValueError:
            request_body_size = 0
        request_body = environ['wsgi.input'].read(request_body_size)
        params = parse_querystring(request_body.decode())
        username = params.get('username', '?')
        _params = params.copy()
        _params['password'] = '********'
        logger.debug('%s: PROCESSED QUERYSTRING: %s', username, _params)
        for req_param in REQUIRED_PARAMS:
            if req_param not in params:
                raise YKAuthError("Missing parameter: '%s'" % req_param)
        client = Client()
        output = client.authenticate(params['username'], params['password'], params['otp'])
    except YKAuthError as err:
        logger.exception('%s: Authentication error: %s', username, err)
        output = False
    except Exception as err:
        logger.exception('%s: Backend error: %s', username, err)
        output = None
        raise
    else:
        logger.info('%s: Authenticated successful', username)
    finally:
        if output == True:
            resp = (200, 'true')
        elif output == False:
            resp = (400, 'false')
        else:
            resp = (500, 'false')
        start_response('%s OK' % resp[0], [('Content-Type', 'text/plain')])
        return [resp[1].encode()]

def decrypt(environ, start_response):
    """
    Handle OTP decryptions
    """
    try:
        params = parse_querystring(environ['QUERY_STRING'])
        logger.debug('PROCESSED QUERYSTRING: %s', params)
        decryptor = Decryptor()
        output = decryptor.decrypt(params.get('otp'))
        output = 'OK counter=%(counter)s low=%(low)s high=%(high)s use=%(use)s\n' % output
    except YKKSMError as err:
        logger.exception('Decryption error: %s', err)
        output = '%s\n' % err
    except Exception as err:
        logger.exception('Backend error: %s', err)
        output = 'ERR Backend failure\n'
    finally:
        start_response('200 OK', [('Content-Type', 'text/plain')])
        return [output.encode()]

def verify(environ, start_response):
    """
    Handle OTP Validation
    """
    apikey = ''.encode()
    username = '?'
    try:
        params = parse_querystring(environ['QUERY_STRING'])
        username = params.get('username', '?')
        logger.debug('%s: PROCESSED QUERYSTRING: %s', username, params)
        verifyer = Verifyer()
        kwargs = params.copy()
        if 'id' in kwargs:
            kwargs.pop('id')
        if 'otp' in kwargs:
            kwargs.pop('otp')
        apikey = verifyer.get_client_apikey(params.get('id'))
        output = verifyer.verify(params.get('id'), params.get('otp'), **kwargs)
    except YKValError as err:
        logger.exception('%s: Validation error: %s', username, err)
        output = '%s' % err
    except Exception as err:
        logger.exception('%s: Backend error: %s', username, err)
        output = 'BACKEND_ERROR'
    finally:
        logger.info('%s: Verified', username)
        return wsgi_response(output, start_response, apikey=apikey, extra=None)

def sync(environ, start_response):
    """
    Handle Sync requests
    """
    local_params = None
    try:
        # Validate caller address
        logger.debug('Received request from %(REMOTE_ADDR)s', environ)
        if environ['REMOTE_ADDR'] not in settings['SYNC_POOL']:
            logger.info('Operation not permitted from IP %(REMOTE_ADDR)s', environ)
            logger.debug('Remote IP %s is not in allowed sync pool: %s',
                         environ['REMOTE_ADDR'], settings['SYNC_POOL'])
            raise YKSyncError('ERROR Authorization failed for %(REMOTE_ADDR)s)' % environ)
        sync_params = parse_querystring(environ['QUERY_STRING'])
        logger.info('Received: %s', sync_params)
        synclib = Sync()
        local_params = synclib.sync_local(sync_params)
        output = 'OK'
        status_code = 200
    except YKSyncError as err:
        output = str(err)
        status_code = 401
    except Exception as err:
        logger.exception('ERROR: %s', err)
        output = 'BACKEND_ERROR'
        status_code = 500
    finally:
        return wsgi_response(output, start_response, apikey=''.encode(),
                             extra=local_params, status=status_code)

def resync(environ, start_response):
    """
    Handle Re-sync requests
    """
    try:
        # Validate caller address
        if environ['REMOTE_ADDR'] not in settings['SYNC_POOL']:
            logger.info('Operation not permitted from IP %(REMOTE_ADDR)s', environ)
            raise YKSyncError('ERROR Authorization failed for %(REMOTE_ADDR)s)' % environ)
        # Parse query and check values
        resync_params = parse_querystring(environ['QUERY_STRING'])
        synclib = Sync()
        output = synclib.resync_local(resync_params)
        status_code = 200
    except YKSyncError as err:
        output = str(err)
        status_code = 401
    except Exception as err:
        logger.exception('ERROR: %s', err)
        output = ''
        status_code = 500
    finally:
        start_response('%d OK' % status_code, [('Content-Type', 'text/plain')])
        return [output.encode()]

def router(environ, start_response):
    """ Simple WSGI router """
    path = environ.get('PATH_INFO', '')
    match = re.match(URI_REGEX, path)
    if not match or not match.groupdict()['resource']:
        start_response('500 Error', [('Content-Type', 'text/plain')])
        return ['Invalid URI'.encode()]
    func = globals()[match.groupdict()['resource']]
    return func(environ, start_response)

def main():
    """ Run a web server to test the application """
    from wsgiref.simple_server import make_server
    logging.basicConfig(format='%(asctime)s %(levelname)s %(module)s %(funcName)s: %(message)s',
                        level=logging.DEBUG)
    srv = make_server('0.0.0.0', 8080, router)
    srv.serve_forever()

if __name__ == '__main__':
    main()
