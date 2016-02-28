"""
yubistack.ykval
~~~~~~~~~~~~~~~

Python Yubikey Stack - Key validation module
"""

import base64
from datetime import datetime
import logging
try:
    import queue
except ImportError:
    import Queue as queue
import re
import threading
import time

import requests

from .config import settings
from .db import DBHandler
from .utils import (
    generate_nonce,
    sign,
    decrypt_otp,
    counters_eq,
    counters_gt,
    counters_gte,
    current_ts,
    parse_sync_response,
)

logger = logging.getLogger(__name__)

# Constants from original yubikey-val implementation
TS_SEC = 0.128 # 1/8
TS_REL_TOLERANCE = 0.3
TS_ABS_TOLERANCE = 20
TOKEN_LEN = 32
OTP_MAX_LEN = 48 # TOKEN_LEN plus public identity of 0..16

class YKValError(Exception):
    """ Errors returned by the application """
    pass

class YKSyncError(Exception):
    """ Errors returned by the application """
    pass

class DBH(DBHandler):
    """
    Extending the generic DBHandler class with the required queries
    """
    def get_client_data(self, client_id):
        """ Lookup client based on the ID """
        query = """SELECT id,
                          secret
                     FROM clients
                    WHERE active = 1
                      AND id = %s"""
        self._execute(query, (client_id,))
        return self._dictfetchone()

    def get_local_params(self, yk_publicname):
        """ Get yubikey parameters from DB """
        query = """SELECT active,
                          modified,
                          yk_publicname,
                          yk_counter,
                          yk_use,
                          yk_low,
                          yk_high,
                          nonce
                     FROM yubikeys
                    WHERE yk_publicname = %s"""
        self._execute(query, (yk_publicname,))
        local_params = self._dictfetchone()
        if not local_params:
            local_params = {
                'active': 1,
                'modified': -1,
                'yk_publicname': yk_publicname,
                'yk_counter': -1,
                'yk_use': -1,
                'yk_low': -1,
                'yk_high': -1,
                'nonce': '0000000000000000',
                'created': current_ts()
            }
            # Key was missing in DB, adding it
            self.add_new_identity(local_params)
            logger.warning('Discovered new identity %s', yk_publicname)
        logger.debug('Auth data: %s', local_params)
        return local_params

    def add_new_identity(self, identity):
        """ Create new key identity """
        query = """INSERT INTO yubikeys (
                       active,
                       created,
                       modified,
                       yk_publicname,
                       yk_counter,
                       yk_use,
                       yk_low,
                       yk_high,
                       nonce
                ) VALUES (
                       %(active)s,
                       %(created)s,
                       %(modified)s,
                       %(yk_publicname)s,
                       %(yk_counter)s,
                       %(yk_use)s,
                       %(yk_low)s,
                       %(yk_high)s,
                       %(nonce)s
                )"""
        try:
            self._execute(query, identity)
            self._db.commit()
        except Exception as err:
            self._db.rollback()
            logger.exception('DB Error: %s', err)
            raise

    def get_queue(self, modified, server_nonce):
        """
        Read all elements from queue
        """
        query = """SELECT server,
                          otp,
                          modified,
                          info
                     FROM queue
                    WHERE modified=%s
                      AND server_nonce = %s"""
        self._execute(query, (modified, server_nonce))
        return self._dictfetchall()

    def remove_from_queue(self, server, modified, server_nonce):
        """
        Remove a single element from queue
        """
        query = """DELETE FROM queue
                         WHERE server = %s
                           AND modified = %s
                           AND server_nonce = %s"""
        try:
            self._execute(query, (server, modified, server_nonce))
            self._db.commit()
        except Exception as err:
            logger.exception('DB Error: %s', err)
            raise

    def null_queue(self, server_nonce):
        """
        NULL queued_time for remaining entries in queue, to allow
        daemon to take care of them as soon as possible.
        """
        query = """UPDATE queue
                      SET queued = NULL
                    WHERE server_nonce = %s"""
        try:
            self._execute(query, (server_nonce,))
            self._db.commit()
        except Exception as err:
            logger.exception('DB Error: %s', err)
            raise

    def update_db_counters(self, params):
        """ Update table with new counter values """
        query = """UPDATE yubikeys
                      SET modified = %(modified)s,
                          yk_counter = %(yk_counter)s,
                          yk_use = %(yk_use)s,
                          yk_low = %(yk_low)s,
                          yk_high = %(yk_high)s,
                          nonce = %(nonce)s
                    WHERE yk_publicname = %(yk_publicname)s
                      AND (yk_counter < %(yk_counter)s
                       OR (yk_counter = %(yk_counter)s
                      AND yk_use < %(yk_use)s))"""
        try:
            self._execute(query, params)
            self._db.commit()
        except Exception as err:
            self._db.rollback()
            logger.exception('DB Error: %s', err)
            raise

    def enqueue(self, otp_params, local_params, server, server_nonce):
        """
        Insert new params into database queue table
        """
        info = 'yk_publicname=%(yk_publicname)s&yk_counter=%(yk_counter)s' % otp_params
        info += '&yk_use=%(yk_use)s&yk_high=%(yk_high)s&yk_low=%(yk_low)s' % otp_params
        info += '&nonce=%(nonce)s' % otp_params
        info += ',&local_counter=%(yk_counter)s&local_use=%(yk_use)s' % local_params
        query = """INSERT INTO queue (
                        queued,
                        modified,
                        otp,
                        server,
                        server_nonce,
                        info
                    ) VALUES (%s, %s, %s, %s, %s, %s)"""
        try:
            self._execute(query, (current_ts(), otp_params['modified'],
                                  otp_params['otp'], server, server_nonce, info))
            self._db.commit()
        except Exception as err:
            self._db.rollback()
            logger.exception('DB Error: %s', err)
            raise

    def get_keys(self, yk_publicname):
        """ Get all keys from DB """
        query = """SELECT yk_publicname
                     FROM yubikeys
                    WHERE active = 1"""
        params = None
        if yk_publicname != 'all':
            query += ' AND yk_publicname = %s'
            params = (yk_publicname,)
        self._execute(query, params)
        return self.cursor.fetchall()

class Sync(object):
    """ Sync object to handle cross synchronization requests """
    def __init__(self, db=None):
        self.db = db if db else DBH(db='ykval')
        self.sync_servers = settings['SYNC_SERVERS']

    def check_sync_input(self, sync_params):
        """ Check for all required parameters """
        REQUIRED_PARAMS = ['modified', 'otp', 'nonce', 'yk_publicname',
                           'yk_counter', 'yk_use', 'yk_high', 'yk_low']
        for req_param in REQUIRED_PARAMS:
            if req_param not in sync_params:
                logger.error("Received request with missing '%s' parameter", req_param)
                raise YKSyncError('MISSING_PARAMETER')
            if req_param not in ('otp', 'nonce', 'yk_publicname') and not \
                (sync_params[req_param] == '-1' or isinstance(sync_params[req_param], int)):
                logger.error("Input parameter '%s' is not correct", req_param)
                raise YKSyncError('MISSING_PARAMETER')

    def check_resync_input(self, resync_params):
        """ Check input parameters """
        if 'yk' not in resync_params:
            logger.error("Received request with missing 'yk' parameter")
            raise YKSyncError('ERROR Missing parameter')
        if not re.match(r'^([cbdefghijklnrtuv]{0,16}|all)$', resync_params['yk']):
            logger.error("Invalid 'yk' value: %(yk)s", resync_params)
            raise YKSyncError('ERROR Unknown yk value: %(yk)s' % resync_params)

    def sync_local(self, sync_params):
        """ Synchronize """
        self.check_sync_input(sync_params)
        local_params = self.db.get_local_params(sync_params['yk_publicname'])
        if not local_params:
            logger.error('Invalid Yubikey: %(yk_publicname)s', sync_params)
            raise YKSyncError('BACKEND_ERROR')

        self.db.update_db_counters(sync_params)
        logger.debug('Local params: %s', local_params)
        logger.debug('Sync request params: %s', sync_params)

        if counters_gte(local_params, sync_params):
            logger.warning('Remote server out of sync')

        if counters_eq(local_params, sync_params):
            if sync_params['modified'] == local_params['modified'] \
                and sync_params['nonce'] == local_params['nonce']:
                # This is not an error. When the remote server received
                # an OTP to verify, it would have sent out sync requests
                # immediately. When the required number of responses had
                # been received, the current implementation discards all
                # additional responses (to return the result to the client
                # as soon as possible). If our response sent last time was
                # discarded, we will end up here when the background
                # ykval-queue processes the sync request again.
                logger.info('Sync request unnecessarily sent')

            if (
                    sync_params['modified'] != local_params['modified'] and
                    sync_params['nonce'] == local_params['nonce']
                ):
                delta_modified = sync_params['modified'] - local_params['modified']
                if delta_modified < -1 or delta_modified > 1:
                    logger.warning('We might have a replay attack. 2 events '
                                   'at different times have generated the same '
                                   'counters. Time difference is %s sec',
                                   delta_modified)

            if sync_params['nonce'] != local_params['nonce']:
                logger.warning('Remote server has received a request to '
                               'validate an already validated OTP')

        if not local_params['active']:
            # The remote server has accepted an OTP from a YubiKey which
            # we would not. We still needed to update our counters with
            # the counters from the OTP thought.
            logger.warning('Received sync-request for de-activated Yubikey '
                           '%(yk_publicname)s', sync_params)
            raise YKSyncError('BAD_OTP')
        return local_params

    def resync_local(self, resync_params):
        """ Re-synchronize """
        self.check_resync_input(resync_params)
        keys = self.db.get_keys(resync_params['yk'])
        server_nonce = generate_nonce()
        for key in keys:
            local_params = self.db.get_local_params(key)
            local_params['otp'] = 'c' * 32 # Fake an OTP
            logger.debug('Auth data: %s', local_params)
            for server in self.sync_servers:
                self.db.enqueue(local_params, local_params, server, server_nonce)
        return 'OK Initiated resync of %(yk)s' % resync_params

    def _fetch_remote(self, dqueue, server, url, timeout):
        """ Make HTTP GET call to remote server """
        try:
            req = requests.get(url, timeout=timeout)
            if req.status_code == 200:
                try:
                    resp_params = parse_sync_response(req.text)
                    dqueue.put({'server': server, 'params': resp_params})
                except ValueError as err:
                    logger.error('Failed to parse response of %s: %s', server, err)
            else:
                logger.warning('Recieved status code %s for %s', req.status_code, url)
        except Exception as err:
            logger.warning('Failed to retrieve %s: %s', url, err)

    def sync_remote(self, otp_params, local_params, server_nonce, required_answers, timeout=1):
        """ Function to synchronize values with other ykval servers """
        # Construct URLs
        responses = []
        dqueue = queue.Queue()
        for row in self.db.get_queue(otp_params['modified'], server_nonce):
            url = '%(server)s?otp=%(otp)s&modified=%(modified)s' % row
            url += '&' + row['info'].split(',')[0]
            _thread = threading.Thread(target=self._fetch_remote, args=(dqueue, row['server'],
                                                                        url, timeout))
            _thread.daemon = True
            _thread.start()
        loop_start = time.time()
        while len(responses) < required_answers and time.time() < loop_start + timeout * 1.5:
            try:
                resp = dqueue.get(timeout=0.2)
                responses.append(resp)
                # Delete entry from table
                self.db.remove_from_queue(resp['server'], otp_params['modified'], server_nonce)
            except queue.Empty:
                pass

        answers = len(responses)
        # Parse response
        valid_answers = 0
        for resp in responses:
            resp_params = resp['params']
            logger.debug('local DB contains %s', local_params)
            logger.debug('response contains %s', resp_params)
            logger.debug('OTP contains %s', otp_params)
            # Update Internal DB (conditional)
            self.db.update_db_counters(resp_params)
            # Check for Warnings
            # https://developers.yubico.com/yubikey-val/doc/ServerReplicationProtocol.html
            # NOTE: We use local_params for validationParams comparison since they are actually
            #       the same in this situation and we have them at hand.
            if counters_gt(local_params, resp_params):
                logger.warning('Remote server out of sync')
            if counters_gt(resp_params, local_params):
                logger.warning('Local server out of sync')
            if counters_eq(resp_params, local_params) \
                and resp_params['nonce'] != local_params['nonce']:
                logger.warning('Servers out of sync. Nonce differs.')
            if counters_eq(resp_params, local_params) \
                and resp_params['modified'] != local_params['modified']:
                logger.warning('Servers out of sync. Modified differs.')
            if counters_gt(resp_params, otp_params):
                logger.warning('OTP is replayed. Sync response counters higher than OTP counters.')
            elif counters_eq(resp_params, otp_params) \
                and resp_params['nonce'] != otp_params['nonce']:
                logger.warning('OTP is replayed. Sync response counters equal to OTP counters and \
nonce differs.')
            else:
                # The answer is ok since a REPLAY was not indicated
                valid_answers += 1
                if required_answers == valid_answers:
                    break

        # NULL queued_time for remaining entries in queue, to allow
        # daemon to take care of them as soon as possible.
        self.db.null_queue(server_nonce)
        return {'answers': answers, 'valid_answers': valid_answers}

class Verifyer(object):
    """ Yubikey OTP validator """
    def __init__(self):
        self.db = DBH(db='ykval')
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
        # CLIENT ID
        if params['client_id'] and not isinstance(params['client_id'], int):
            logger.error('id provided in request must be an integer')
            raise YKValError('MISSING_PARAMETER')
        # OTP
        if not TOKEN_LEN <= len(params['otp']) <= OTP_MAX_LEN:
            logger.error('Incorrect OTP length: %(otp)s', params)
            raise YKValError('BAD_OTP')
        if not re.match(r'^[cbdefghijklnrtuv]+$', params['otp']):
            logger.error('Invalid OTP: %(otp)s', params)
            raise YKValError('BAD_OTP')
        # NONCE:
        # - If client_id is not provided, we're using a Native stack call
        if params['client_id'] and params['proto_ver'] >= 2.0 and not params['nonce']:
            logger.error('Nonce is missing and protocol version >= 2.0')
            raise YKValError('MISSING_PARAMETER')
        if params['nonce'] and not re.match(r'^[A-Za-z0-9]+$', params['nonce']):
            logger.error('Nonce is provided but not correct')
            raise YKValError('MISSING_PARAMETER')
        if params['nonce'] and not 16 <= len(params['nonce']) <= 40:
            logger.error('Nonce too short or too long')
            raise YKValError('MISSING_PARAMETER')
        # TIMESTAMP
        #   NOTE: Timestamp parameter is not checked since current protocol says
        #   that 1 means request timestamp and anything else is discarded.
        # TIMEOUT
        if not isinstance(params['timeout'], int):
            logger.error('timeout is provided but not correct')
            raise YKValError('MISSING_PARAMETER')
        # SYNC LEVEL
        if not (isinstance(params['sync_level'], int) and 0 <= params['sync_level'] <= 100):
            logger.error('SL (sync level) is provided but not correct')
            raise YKValError('MISSING_PARAMETER')

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

    def check_client_signature(self, apikey, params):
        """
        Check client signature if 'h' parameter was provided for request

        Args:
            apikey: Client's API key (from DB)
            params: Request parameter

        Returns:
            None

        Raises:
            YKValError('BAD_SIGNATURE') if request was not encoded with
            the given apikey
        """
        if params['signature']:
            recieved_data = params.copy()
            recieved_data.pop('signature')
            recieved_data.pop('proto_ver')
            new_signature = sign(recieved_data, apikey)
            if params['signature'] != new_signature:
                logger.error('Client hmac=%s, server hmac=%s',
                             params['signature'], new_signature)
                raise YKValError('BAD_SIGNATURE')

    def decode_otp(self, otp):
        """ Decode OTP from input """
        try:
            otp_info = decrypt_otp(otp, urls=settings['YKKSM_SERVERS'],
                                   decryptor=self.decryptor)
        except Exception as err:
            logger.exception('Decryption error: %s', err)
            otp_info = None
        if not otp_info:
            raise YKValError('BAD_OTP')
        logger.debug('Decrypted OTP: %s', otp_info)
        return otp_info

    def build_otp_params(self, params, otp_info):
        """ Build OTP params """
        return {
            'modified': current_ts(),
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
        if counters_eq(local_params, otp_params) \
            and local_params['nonce'] == otp_params['nonce']:
            logger.warning('Replayed request')
            raise YKValError('REPLAYED_REQUEST')
        # Check the OTP counters against local DB
        if counters_gte(local_params, otp_params):
            logger.warning('Replayed OTP: Local counters higher (%s > %s)',
                           local_params, otp_params)
            raise YKValError('REPLAYED_OTP')
        # Valid OTP, update DB
        try:
            self.db.update_db_counters(otp_params)
        except:
            logger.error('Failed to update yubikey counters in database')
            raise YKValError('BACKEND_ERROR')

    def replicate(self, otp_params, local_params, server_nonce):
        """ Handle sync across the cluster """
        try:
            for server in settings['SYNC_SERVERS']:
                self.db.enqueue(otp_params, local_params, server, server_nonce)
        except:
            logger.error('ykval-verify:critical:failed to queue sync requests')
            raise YKValError('BACKEND_ERROR')

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
        logger.info('ykval-verify:notice:synclevel=%s server_count=%s req_answers=%s answers=%s \
valid_answers=%s sl_success_rate=%s timeout=%s', self.sync_level, len(self.sync_servers),
                    req_answers, sync_metrics['answers'], sync_metrics['valid_answers'],
                    sync_level_success_rate, self.timeout)

        if not sync_success:
            # sync returned false, indicating that either at least 1 answer
            # marked OTP as invalid or there were not enough answers
            logger.error('ykval-verify:notice:Sync failed')
            if sync_metrics['valid_answers'] != sync_metrics['answers']:
                raise YKValError('REPLAYED_OTP')
            else:
                #self.extra['sl'] = self.sync_level_success_rate
                raise YKValError('NOT_ENOUGH_ANSWERS')

    def phishing_test(self, otp_params, local_params):
        """ Run a timing phishing test """
        # Recreate parameters to make phising test work out
        if otp_params['yk_counter'] == local_params['yk_counter'] \
            and otp_params['yk_use'] > local_params['yk_use']:
            new_ts = (otp_params['yk_high'] << 16) + otp_params['yk_low']
            old_ts = (local_params['yk_high'] << 16) + local_params['yk_low']
            ts_diff = new_ts - old_ts
            ts_delta = ts_diff * TS_SEC

            # Check real time
            last_time = local_params['modified']
            now = datetime.utcnow()
            elapsed = int(now.strftime('%s')) - last_time
            deviation = abs(elapsed - ts_delta)

            # Time delta server might verify multiple OTPS in a row. In such case validation server
            # doesn't have time to tick a whole second and we need to avoid division by zero.
            if elapsed:
                percent = deviation / elapsed
            else:
                percent = 1
            logger.info('Timestamp seen=%s this=%s delta=%s secs=%s accessed=%s (%s) '
                        'now=%s (%s) elapsed=%s deviation=%s secs or %s%%', old_ts, new_ts,
                        ts_delta, ts_diff, last_time, datetime.utcfromtimestamp(last_time),
                        int(now.strftime('%s')), now, elapsed, deviation, percent)
            if deviation > TS_ABS_TOLERANCE and percent > TS_REL_TOLERANCE:
                logger.warning('OTP failed phishing test')
                raise YKValError('DELAYED_OTP')

    def verify(self, otp, client_id=None, nonce=None, signature=None,
               timestamp=0, timeout=None, sync_level=None, proto_ver=2.0):
        """
        Yubico OTP Validation Protocol V2.0 Implementation

        Args:
            otp: The OTP from the YubiKey
            client_id: Specifies the requestor so that the end-point
                       can retrieve correct shared secret for
                       signing the response.
            nonce: A 16 to 40 character long string with random unique data
            signature: The optional HMAC-SHA1 signature for the request
            timestamp: Timestamp=1 requests timestamp and session
                       counter information in the response
            timeout: Number of seconds to wait for sync responses;
                     if absent, let the server decide
            sync_level: A value 0 to 100 indicating percentage of
                        syncing required by client, or strings "fast" or
                        "secure" to use server-configured values;
                        if absent, let the server decide
            proto_ver: Version of validation protocol (min 2.0)

        Returns:
            A signed response with status=OK if the OTP is valid

        Raises:
            YKValError('BAD_OTP'): The OTP is invalid format
            YKValError('REPLAYED_OTP'): The OTP has already been seen by the service
            YKValError('BAD_SIGNATURE'): The HMAC signature verification failed
            YKValError('MISSING_PARAMETER'): The request lacks a parameter
            YKValError('NO_SUCH_CLIENT'): The request id does not exist
            YKValError('OPERATION_NOT_ALLOWED'): The request id is not allowed to verify OTPs
            YKValError('BACKEND_ERROR'): Unexpected error in the server
            YKValError('NOT_ENOUGH_ANSWERS'): Server could not get requested number
                                              of syncs during before timeout
            YKValError('REPLAYED_REQUEST'): Server has seen the OTP/Nonce combination before


        Verify OTP process:
            1. sanitize input parameters
            2. verify the requesting client (id and signature must match)
            3. decrypt OTP (YKKSM)
            4. compare old OTP counters with the given OTP counters and check for replay
            5. replicate new OTP counters to remote servers and check for replay on other servers
            6. check for phishing: OTP has to be used within a timeframe otherwise mark as expired
            7. prepare response: Sign the response with the right client key
        """

        ###################################
        # STEP 1: sanitize input parameters
        ###################################
        if proto_ver < 2.0:
            logger.error('Protocol version %f (<2.0) is not supported.',
                         proto_ver)
            raise YKValError('BACKEND_ERROR')
        self.timeout = timeout if timeout else settings['SYNC_TIMEOUT']
        self.sync_level = sync_level if sync_level else settings['SYNC_LEVEL']
        server_nonce = generate_nonce()
        params = {
            'client_id': client_id,
            'otp': otp,
            'nonce': nonce if nonce else server_nonce,
            'signature': signature,
            'timestamp': timestamp,
            'timeout': self.timeout,
            'sync_level': self.sync_level,
            'proto_ver': proto_ver,
        }
        extra_params = {
            'otp': otp,
            'nonce': params['nonce']
        }
        # Check sanity of parameters
        self.check_parameters(params)

        ######################################
        # STEP 2: verify the requesting client
        ######################################
        apikey = self.get_client_apikey(client_id)
        self.check_client_signature(apikey, params)

        #####################
        # STEP 3: decrypt OTP
        #####################
        otp_info = self.decode_otp(otp)

        #######################################
        # STEP 4: compare old OTP counters with
        #         the given OTP counters and
        #         check for replay
        #######################################
        # Get old parameters (counters) for the token
        local_params = self.db.get_local_params(otp[:-TOKEN_LEN])
        if not local_params['active']:
            logger.error('De-activated Yubikey: %(yk_publicname)s', local_params)
            raise YKValError('BAD_OTP')
        # Build the new parameters (counters) for the given OTP
        otp_params = self.build_otp_params(params, otp_info)
        # Validate OTP, check for replayed request or replayed OTP
        self.validate_otp(otp_params, local_params)

        #####################################
        # STEP 5: replicate new OTP counters
        #         to remote servers and check
        #         for replay on other servers
        #####################################
        sync_level_success_rate = self.replicate(otp_params, local_params, server_nonce)

        #######################################
        # STEP 6: check for phishing, OTP has
        #         to be used within a timeframe
        #         otherwise mark as expired
        #######################################
        self.phishing_test(otp_params, local_params)

        ##########################
        # STEP 7: Prepare response
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
        signature = sign(response, apikey)
        response['signature'] = signature
        return response
