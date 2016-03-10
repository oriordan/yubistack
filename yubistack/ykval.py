"""
yubistack.ykval
~~~~~~~~~~~~~~~

Python Yubikey Stack - Key validation module
"""

import base64
from datetime import datetime
import logging
import re
import time

import requests

from .config import (
    settings,
    TS_SEC,
    TS_REL_TOLERANCE,
    TOKEN_LEN,
    OTP_MAX_LEN,
)
from .db import DBHandler
from .exceptions import YKValError
from .utils import (
    generate_nonce,
    counters_eq,
    counters_gte,
)
from .yksync import Sync

logger = logging.getLogger(__name__)

class Validator:
    """ Yubikey OTP validator """
    def __init__(self):
        self.db = DBHandler(db='ykval')
        if settings['USE_NATIVE_YKKSM']:
            from .ykksm import Decryptor
            self.decryptor = Decryptor()
        else:
            self.decryptor = None
        self.sync_servers = settings['SYNC_SERVERS']
        self.default_sync_level = settings['SYNC_LEVEL']
        # Below parameters are valid from protocol version >= 2.0
        self.sync_level = None
        self.timeout = None

    def check_parameters(self, params):
        """ Perform Sanity check on parameters """
        params['token_id'] = '?' * 12
        # OTP
        if not TOKEN_LEN <= len(params['otp']) <= OTP_MAX_LEN:
            logger.error('[%(token_id)s] Incorrect OTP length: %(otp)s', params)
            raise YKValError('BAD_OTP')
        params['token_id'] = params['otp'][:-TOKEN_LEN]
        if not re.match(r'^[cbdefghijklnrtuv]+$', params['otp']):
            logger.error('[%(token_id)s] Invalid OTP: %(otp)s', params)
            raise YKValError('BAD_OTP')
        # CLIENT ID
        if params['client_id'] and not isinstance(params['client_id'], int):
            logger.error('[%(token_id)s] id provided in request '
                         '(%(client_id)s must be an integer', params)
            raise YKValError('INVALID_PARAMETER', 'client_id')
        # NONCE:
        # - If client_id is not provided, we're using a Native stack call
        if params['client_id'] and not params['nonce']:
            logger.error('[%(token_id)s] Nonce is missing', params)
            raise YKValError('MISSING_PARAMETER', 'nonce')
        if params['nonce'] and not re.match(r'^[A-Za-z0-9]+$', params['nonce']):
            logger.error('[%(token_id)s] Nonce is provided but not correct', params)
            raise YKValError('INVALID_PARAMETER', 'nonce')
        if params['nonce'] and not 16 <= len(params['nonce']) <= 40:
            logger.error('[%(token_id)s] Nonce too short or too long (%(nonce)s)', params)
            raise YKValError('INVALID_PARAMETER', 'nonce')
        # TIMESTAMP
        #   NOTE: Timestamp parameter is not checked since current protocol says
        #   that 1 means request timestamp and anything else is discarded.
        # TIMEOUT
        if not isinstance(params['timeout'], int):
            logger.error('[%(token_id)s] timeout is provided but not correct (%(timeout)s)',
                         params)
            raise YKValError('INVALID_PARAMETER', 'timeout')
        # SYNC LEVEL
        if not (isinstance(params['sync_level'], int) and 0 <= params['sync_level'] <= 100):
            logger.error('[%(token_id)s] SL (sync level) is provided but '
                         'not correct (%(sync_level)s)', params)
            raise YKValError('INVALID_PARAMETER', 'sync_level')

    def get_client_apikey(self, client_id):
        """
        Get Client info from DB

        Args:
            client_id: Integer ID number of the client.
                       Corresponding API key will be retrieved from DB

        Returns:
            b64decoded client secret (apikey)

        Raises:
            YKValError('NO_SUCH_CLIENT') if client doesn't exist
        """
        if not client_id:
            return ''.encode()
        client_data = self.db.get_client_data(client_id)
        logger.debug('Client data: %s', client_data)
        if not client_data:
            logger.error('Invalid client id: %s', client_id)
            raise YKValError('NO_SUCH_CLIENT')
        return base64.b64decode(client_data['secret'])

    def decode_otp(self, otp):
        """
        Call out to KSM to decrypt OTP
        """
        if self.decryptor:
            data = self.decryptor.decrypt(otp)
            return dict([(k, int(v, 16)) for k, v in data.items()])
        elif settings['YKKSM_SERVERS']:
            # TODO: Support for async req for multiple servers
            for url in settings['YKKSM_SERVERS']:
                req = requests.get(url, params={'otp': otp}, headers={'Accept': 'application/json'})
                logger.debug('[%s] YK-KSM response: %s (status_code: %s)',
                             otp[:-TOKEN_LEN], req.text, req.status_code)
                if req.headers['Content-Type'] == 'application/json' and req.status_code == 200:
                    return dict([(k, int(v, 16)) for k, v in req.json().items()])
                if req.text.startswith('OK'):
                    resp = {}
                    for i in req.text.split()[1:]:
                        key, val = i.split('=')
                        resp[key] = int(val, 16)
                    return resp
            raise YKValError('BAD_OTP')
        logger.error("No KSM service provided. Can't decrypt OTP.")
        raise YKValError('BACKEND_ERROR', 'No KSM service found')

    def build_otp_params(self, params, otp_info):
        """ Build OTP params """
        return {
            'modified': int(time.time()),
            'otp': params['otp'],
            'nonce': params['nonce'],
            'yk_publicname': params['otp'][:-TOKEN_LEN],
            'yk_counter': int(otp_info['counter']),
            'yk_use': int(otp_info['use']),
            'yk_high': otp_info['high'],
            'yk_low': otp_info['low'],
        }

    def validate_otp(self, otp_params, local_params):
        """ Validate OTP """
        # First check if OTP is seen with the same nonce, in such case we have an replayed request
        if counters_eq(local_params, otp_params) and local_params['nonce'] == otp_params['nonce']:
            logger.error('[%(yk_publicname)s] Replayed request '
                         '(OTP: %(otp)s, Nonce: %(nonce)s)', otp_params)
            raise YKValError('REPLAYED_REQUEST')
        # Check the OTP counters against local DB
        if counters_gte(local_params, otp_params):
            logger.error('[%s] Replayed OTP: Local counters higher (%s > %s)',
                         otp_params['yk_publicname'], local_params, otp_params)
            raise YKValError('REPLAYED_OTP')
        # Valid OTP, update DB
        self.db.update_db_counters(otp_params)

    def replicate(self, otp_params, local_params, server_nonce):
        """ Handle sync across the cluster """
        for server in settings['SYNC_SERVERS']:
            self.db.enqueue(otp_params, local_params, server, server_nonce)

        req_answers = round(len(self.sync_servers) * float(self.sync_level) / 100.0)
        if req_answers:
            sync = Sync(self.db)
            sync_metrics = sync.sync_remote(otp_params, local_params, server_nonce,
                                            req_answers, self.timeout)
            sync_success = sync_metrics['valid_answers'] == req_answers
            sync_level_success_rate = 100.0 * sync_metrics['valid_answers'] / len(self.sync_servers)
        else:
            sync_success = True
            sync_level_success_rate = 0
            sync_metrics = {'answers': 0, 'valid_answers': 0}
        logger.info('[%s] Sync details: synclevel=%s server_count=%s req_answers=%s '
                    'answers=%s valid_answers=%s sl_success_rate=%.3f timeout=%s',
                    otp_params['yk_publicname'], self.sync_level, len(self.sync_servers),
                    req_answers, sync_metrics['answers'], sync_metrics['valid_answers'],
                    sync_level_success_rate, self.timeout)

        if not sync_success:
            # sync returned false, indicating that either at least 1 answer
            # marked OTP as invalid or there were not enough answers
            if sync_metrics['valid_answers'] != sync_metrics['answers']:
                logger.error('[%(yk_publicname)s] Remote server claims Replayed '
                             'request (OTP: %(otp)s, Nonce: %(nonce)s)', otp_params)
                raise YKValError('REPLAYED_OTP')
            else:
                logger.error('[%s] Failed to synchronize with %s '
                             'servers (%s answers, %s valid)', otp_params['yk_publicname'],
                             req_answers, sync_metrics['answers'], sync_metrics['valid_answers'])
                raise YKValError('NOT_ENOUGH_ANSWERS')
        return sync_level_success_rate

    def phishing_test(self, otp_params, local_params):
        """
        Run a test against token's internal timer

        If the token was generated seconds before the login attempt
        mark the OTP as invalid.
        """
        # Only check token timestamps if TS_ABS_TOLERANCE is
        # set to a proper value or token was not plugged out
        if (
                settings['TS_ABS_TOLERANCE'] == 0 or
                otp_params['yk_counter'] != local_params['yk_counter']
            ):
            return
        new_ts = (otp_params['yk_high'] << 16) + otp_params['yk_low']
        old_ts = (local_params['yk_high'] << 16) + local_params['yk_low']
        ts_delta = (new_ts - old_ts) * TS_SEC

        # Check real time
        last_time = local_params['modified']
        now = int(time.time())
        elapsed = now - last_time
        deviation = abs(elapsed - ts_delta)

        # Time delta server might verify multiple OTPs in a row. In such case validation server
        # doesn't have time to tick a whole second and we need to avoid division by zero.
        if elapsed:
            percent = deviation / elapsed
        else:
            percent = 1
        if deviation > settings['TS_ABS_TOLERANCE'] and percent > TS_REL_TOLERANCE:
            logger.error('[%s] OTP Expired: TOKEN TS DIFF: %s, '
                         'ACCESS TS DIFF: %s, DEVIATION: %s (sec) or %s%%',
                         otp_params['yk_publicname'], ts_delta, elapsed, deviation, percent)
            raise YKValError('DELAYED_OTP')

    def verify(self, otp, client_id=None, nonce=None, timestamp=0,
               timeout=None, sync_level=None):
        """
        Yubico OTP Validation Protocol V2.0 Implementation

        Args:
            otp: The OTP from the YubiKey
            client_id: Specifies the requestor so that the end-point
                       can retrieve correct shared secret for
                       signing the response.
            nonce: A 16 to 40 character long string with random unique data
            timestamp: Timestamp=1 requests timestamp and session
                       counter information in the response
            timeout: Number of seconds to wait for sync responses;
                     if absent, let the server decide
            sync_level: A value 0 to 100 indicating percentage of
                        syncing required by client, or strings "fast" or
                        "secure" to use server-configured values;
                        if absent, let the server decide

        Returns:
            A signed response with status=OK if the OTP is valid

        Raises:
            YKValError('BAD_OTP'): The OTP is invalid format
            YKValError('REPLAYED_OTP'): The OTP has already been seen by the service
            YKValError('MISSING_PARAMETER'): The request lacks a parameter
            YKValError('NO_SUCH_CLIENT'): The request id does not exist
            YKValError('BACKEND_ERROR'): Unexpected error in the server
            YKValError('NOT_ENOUGH_ANSWERS'): Server could not get requested number
                                              of syncs during before timeout
            YKValError('REPLAYED_REQUEST'): Server has seen the OTP/Nonce combination before


        Verify OTP process:
            1. sanitize input parameters
            2. decrypt OTP (YKKSM)
            3. compare old OTP counters with the given OTP counters and check for replay
            4. replicate new OTP counters to remote servers and check for replay on other servers
            5. check for phishing: OTP has to be used within a timeframe otherwise mark as expired
            6. prepare response: Sign the response with the right client key
        """

        ###################################
        # STEP 1: sanitize input parameters
        ###################################
        self.timeout = timeout if timeout else settings['SYNC_TIMEOUT']
        self.sync_level = sync_level if sync_level else settings['SYNC_LEVEL']
        server_nonce = generate_nonce()
        params = {
            'client_id': client_id,
            'otp': otp,
            'nonce': nonce if nonce else server_nonce,
            'timestamp': timestamp,
            'timeout': self.timeout,
            'sync_level': self.sync_level,
        }
        extra_params = {
            'otp': otp,
            'nonce': params['nonce']
        }
        # Check sanity of parameters
        self.check_parameters(params)

        #####################
        # STEP 2: decrypt OTP
        #####################
        otp_info = self.decode_otp(otp)

        #######################################
        # STEP 3: compare old OTP counters with
        #         the given OTP counters and
        #         check for replay
        #######################################
        # Get old parameters (counters) for the token
        local_params = self.db.get_local_params(otp[:-TOKEN_LEN])
        if not local_params['active']:
            logger.error('[%(yk_publicname)s]: De-activated Yubikey', local_params)
            raise YKValError('DISABLED_TOKEN')
        # Build the new parameters (counters) for the given OTP
        otp_params = self.build_otp_params(params, otp_info)
        # Validate OTP, check for replayed request or replayed OTP
        self.validate_otp(otp_params, local_params)

        #####################################
        # STEP 4: replicate new OTP counters
        #         to remote servers and check
        #         for replay on other servers
        #####################################
        sync_level_success_rate = self.replicate(otp_params, local_params, server_nonce)

        #######################################
        # STEP 5: check for phishing, OTP has
        #         to be used within a timeframe
        #         otherwise mark as expired
        #######################################
        self.phishing_test(otp_params, local_params)

        ##########################
        # STEP 6: Prepare response
        ##########################
        extra_params['sl'] = sync_level_success_rate
        if timestamp == 1:
            extra_params['timestamp'] = (otp_info['yk_high'] << 16) + otp_info['yk_low']
            extra_params['sessioncounter'] = otp_info['yk_counter']
            extra_params['sessionuse'] = otp_info['yk_use']
        response = {
            'status': 'OK',
            'time': datetime.utcnow().isoformat().replace('.', 'Z')[:-2]
        }
        response.update(extra_params)
        return response
