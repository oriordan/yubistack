"""
yubistack.ykval
~~~~~~~~~~~~~~~

Python Yubikey Stack - Key validation module
"""

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
from .exceptions import YKSyncError
from .utils import (
    generate_nonce,
    counters_eq,
    counters_gt,
    counters_gte,
    parse_sync_response,
)

logger = logging.getLogger(__name__)
requests_log = logging.getLogger('requests')
requests_log.setLevel(logging.WARNING if logger.getEffectiveLevel() != 10 else logging.DEBUG)

REQUIRED_PARAMS = ['modified', 'otp', 'nonce', 'yk_publicname',
                   'yk_counter', 'yk_use', 'yk_high', 'yk_low']
class Sync(object):
    """ Sync object to handle cross synchronization requests """
    def __init__(self, db=None):
        self.db = db if db else DBHandler(db='ykval')
        self.sync_servers = settings['SYNC_SERVERS']

    def check_sync_input(self, sync_params):
        """ Check for all required parameters """
        for req_param in REQUIRED_PARAMS:
            if req_param not in sync_params:
                logger.error("Received request with missing '%s' parameter", req_param)
                raise YKSyncError('MISSING_PARAMETER', req_param)
            if req_param not in ('otp', 'nonce', 'yk_publicname') and not \
                (sync_params[req_param] == '-1' or isinstance(sync_params[req_param], int)):
                logger.error("Input parameter '%s' is not correct", req_param)
                raise YKSyncError('INVALID_PARAMETER', req_param)

    def check_resync_input(self, resync_params):
        """ Check input parameters """
        if 'yk' not in resync_params:
            logger.error("Received request with missing 'yk' parameter")
            raise YKSyncError('MISSING_PARAMETER', 'yk')
        if not re.match(r'^([cbdefghijklnrtuv]{0,16}|all)$', resync_params['yk']):
            logger.error("Invalid 'yk' value: %(yk)s", resync_params)
            raise YKSyncError('INVALID_PARAMETER', 'yk')

    def sync_local(self, sync_params):
        """ Synchronize """
        self.check_sync_input(sync_params)
        local_params = self.db.get_local_params(sync_params['yk_publicname'])
        self.db.update_db_counters(sync_params)
        logger.debug('[%s] Local params: %s',
                     sync_params['yk_publicname'], local_params)
        logger.debug('[%s] Sync request params: %s',
                     sync_params['yk_publicname'], sync_params)

        if counters_gte(local_params, sync_params):
            logger.warning('[%(yk_publicname)s] Remote server out of sync', sync_params)

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
                logger.info('[%(yk_publicname)s] Sync request unnecessarily sent',
                            sync_params)

            if (
                    sync_params['modified'] != local_params['modified'] and
                    sync_params['nonce'] == local_params['nonce']
                ):
                delta_modified = sync_params['modified'] - local_params['modified']
                if delta_modified < -1 or delta_modified > 1:
                    logger.warning('[%s] We might have a replay attack. 2 events '
                                   'at different times have generated the same '
                                   'counters. Time difference is %s sec',
                                   sync_params['yk_publicname'], delta_modified)

            if sync_params['nonce'] != local_params['nonce']:
                logger.warning('[%(yk_publicname)s] Remote server has received '
                               'a request to validate an already validated OTP', sync_params)

        if not local_params['active']:
            # The remote server has accepted an OTP from a YubiKey which
            # we would not. We still needed to update our counters with
            # the counters from the OTP thought.
            logger.error('[%(yk_publicname)s] Received sync-request for '
                         'de-activated Yubikey', sync_params)
            raise YKSyncError('DISABLED_TOKEN')
        return local_params

    def resync_local(self, resync_params):
        """ Re-synchronize """
        self.check_resync_input(resync_params)
        keys = self.db.get_keys(resync_params['yk'])
        server_nonce = generate_nonce()
        for key in keys:
            local_params = self.db.get_local_params(key['yk_publicname'])
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
            _thread = threading.Thread(target=self._fetch_remote,
                                       args=(dqueue, row['server'], url, timeout))
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
            logger.debug('[%s] local DB contains %s',
                         otp_params['yk_publicname'], local_params)
            logger.debug('[%s] response contains %s',
                         otp_params['yk_publicname'], resp_params)
            logger.debug('[%s] OTP contains %s',
                         otp_params['yk_publicname'], otp_params)
            # Update Internal DB (conditional)
            self.db.update_db_counters(resp_params)
            # Check for Warnings
            # https://developers.yubico.com/yubikey-val/doc/ServerReplicationProtocol.html
            # NOTE: We use local_params for validationParams comparison since they are actually
            #       the same in this situation and we have them at hand.
            if counters_gt(local_params, resp_params):
                logger.warning('[%(yk_publicname)s] Remote server out of sync', otp_params)
            if counters_gt(resp_params, local_params):
                logger.warning('[%(yk_publicname)s] Local server out of sync', otp_params)
            if counters_eq(resp_params, local_params) \
                and resp_params['nonce'] != local_params['nonce']:
                logger.warning('[%(yk_publicname)s] Servers out of sync. '
                               'Nonce differs.', otp_params)
            if counters_eq(resp_params, local_params) \
                and resp_params['modified'] != local_params['modified']:
                logger.warning('[%(yk_publicname)s] Servers out of sync. '
                               'Modified differs.', otp_params)
            if counters_gt(resp_params, otp_params):
                logger.warning('[%(yk_publicname)s] OTP is replayed. '
                               'Sync response counters higher than OTP counters.', otp_params)
            elif counters_eq(resp_params, otp_params) \
                and resp_params['nonce'] != otp_params['nonce']:
                logger.warning('[%(yk_publicname)s] OTP is replayed. Sync '
                               'response counters equal to OTP counters and nonce '
                               'differs.', otp_params)
            else:
                # The answer is ok since a REPLAY was not indicated
                valid_answers += 1
                if required_answers == valid_answers:
                    break

        # NULL queued_time for remaining entries in queue, to allow
        # daemon to take care of them as soon as possible.
        self.db.null_queue(server_nonce)
        return {'answers': answers, 'valid_answers': valid_answers}
