"""
yubistack.replicate
~~~~~~~~~~~~~~~~~~~

Script to run through the queue and ensure
that remote servers are updated.
"""

import logging

import requests

from yubistack.utils import (
    counters_eq,
    counters_gt,
    parse_querystring,
    parse_sync_response,
)
from yubistack.ykval import Sync

logger = logging.getLogger(__name__)
requests_log = logging.getLogger('requests')
requests_log.setLevel(logging.WARNING if logger.getEffectiveLevel() != 10 else logging.DEBUG)

def main():
    """
    Main program
    """
    sync = Sync()
    queue_data = sync.db.read_queue()
    servers = set([x['server'] for x in queue_data])

    for server in servers:
        logger.debug('Processing queue for server %s', server)
        items = [x for x in queue_data if x['server'] == server]
        try:
            for item in items[:20]:
                url = '%s?otp=%s&modified=%s&%s' % (item['server'], item['otp'], item['modified'],
                                                    item['info'].split(',')[0])
                resp = requests.get(url)
                if resp.status_code == 200:
                    if resp.text.rstrip().endswith('status=OK'):
                        # Read remote counters
                        remote_params = parse_sync_response(resp.text)
                        # Update local counters
                        sync.db.update_db_counters(remote_params)
                        # Get OTP counters
                        otp_params = parse_querystring(item['info'].split(',')[0])
                        # Get validation counters before processing the OTP
                        validation_params = parse_querystring(item['info'].split(',')[1])
                        validation_params = {'yk_counter': validation_params['local_counter'],
                                             'yk_use': validation_params['local_use']}
                        # Get current local counters
                        local_params = sync.db.get_local_params(otp_params['yk_publicname'])

                        if counters_gt(validation_params, remote_params):
                            logger.info('[%s]: Remote server out of sync compared to counters '
                                        'at validation request time.', server)
                        if counters_gt(remote_params, validation_params):
                            if counters_eq(remote_params, otp_params):
                                logger.info('[%s]: Remote server had received the current '
                                            'counter values already.', server)
                            else:
                                logger.info('Local server out of sync compared to counters '
                                            'at validation request time.')
                        if counters_gt(local_params, remote_params):
                            logger.info('Local server out of sync compared to current local '
                                        'counters. Local server updated.')
                        if counters_gt(remote_params, otp_params):
                            logger.info('[%s]: Remote server has higher counters than OTP. '
                                        'This response would have marked the OTP as invalid.',
                                        server)
                        elif counters_eq(remote_params, otp_params) and \
                                remote_params['nonce'] != otp_params['nonce']:
                            logger.info('[%s]: Remote server has equal counters as OTP '
                                        'and nonce differs. This response would have '
                                        'marked the OTP as invalid.', server)
                        # Delete queue entry
                        sync.db.remove_from_queue(server, item['modified'], item['server_nonce'])
                    elif resp.text.rstrip().endswith('status=BAD_OTP'):
                        logger.warning('[%s]: Remote server says BAD_OTP, pointless to try '
                                       'again, removing from queue.', server)
                        # Delete queue entry
                        sync.db.remove_from_queue(server, item['modified'], item['server_nonce'])
                    else:
                        logger.error('[%s]: Remote server refused our sync request. '
                                     'Check remote server logs.', server)
                else:
                    logger.error('[%s]: Remote server refused our sync request. '
                                 'Check remote server logs.', server)
        except (requests.exceptions.Timeout,
                requests.exceptions.ConnectionError) as err:
            logger.error('Failed to connect to server %s: %s', server, err)
            continue

if __name__ == '__main__':
    main()
