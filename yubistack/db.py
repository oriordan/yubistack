"""
ykval.db
~~~~~~~~

Database Handler & queries
"""

import logging
import time

from .config import settings

logger = logging.getLogger(__name__)

class DBHandler:
    """ Database handler wrapper """
    def __init__(self, db):
        self.settings = settings['DATABASES'][db]
        # This is not nice, but works well.
        # We need to catch OperationalError in the _execute functon, so
        # the db driver has to be available
        if self.settings.get('ENGINE', 'mysql') == 'mysql':
            import MySQLdb as dbdriver
        elif self.settings['ENGINE'] == 'postgres':
            import psycopg2 as dbdriver
        elif self.settings['ENGINE'] == 'sqlite':
            import sqlite3 as dbdriver
        else:
            raise ValueError('Invalid Database configuration')
        self.dbdriver = dbdriver
        self._connect()

    def _connect(self):
        """ Connect to the database """
        if self.settings.get('ENGINE', 'mysql') == 'mysql':
            self._db = self.dbdriver.connect(self.settings['HOST'],
                                             self.settings['USER'],
                                             self.settings['PASSWORD'],
                                             self.settings['NAME'],
                                             self.settings.get('PORT', 3306))
        elif self.settings['ENGINE'] == 'postgres':
            self._db = self.dbdriver.connect(database=self.settings['NAME'],
                                             user=self.settings['USER'],
                                             password=self.settings['PASSWORD'],
                                             host=self.settings['HOST'])
        elif self.settings['ENGINE'] == 'sqlite':
            self._db = self.dbdriver.connect(self.settings['NAME'])
        self.cursor = self._db.cursor()

    def _execute(self, query, params=None, retry=False):
        """ Abstract the cursor execute function to handle sqlite syntax """
        if self.settings.get('ENGINE') == 'sqlite':
            if '%s' in query and params:
                query = query.replace('%s', '?')
            elif '%(' in query and params:
                query = query.replace('%(', ':').replace(')s', '')
        if logger.getEffectiveLevel() == logging.DEBUG:
            _query = ' '.join([x.strip() for x in query.split()])
            logger.debug('QUERY: %s PARAMS: %s', _query, params)
        try:
            rowcount = self.cursor.execute(query, params)
            self._db.commit()
            return rowcount
        except (AttributeError, self.dbdriver.OperationalError) as err:
            if not retry:
                logger.debug('Database reconnect due to error: %s', err)
                self._connect()
                return self._execute(query, params, retry=True)
            else:
                raise
        except Exception as err:
            logger.exception('Database error: %s', err)
            raise

    def _dictfetchall(self):
        """ Wrapper to return DB results in dict format """
        return [dict(zip([col[0] for col in self.cursor.description], row)) \
                for row in self.cursor.fetchall()]

    def _dictfetchone(self):
        """ Wrapper to return DB results in dict format """
        data = self._dictfetchall()
        if data:
            return data[0]
        return {}

    #################
    # YKAUTH QUERIES
    #################
    def get_user(self, username):
        """
        Read user information for Yubiauth
        """
        query = """SELECT users.attribute_association_id AS users_attribute_association_id,
                          users.id AS users_id, users.name AS users_name,
                          users.auth AS users_auth
                     FROM users
                    WHERE users.name = %s"""
        self._execute(query, (username,))
        return self._dictfetchone()

    def get_token(self, user_id, token_id):
        """
        Read user attribute information for Yubiauth
        """
        query = """SELECT yubikeys.attribute_association_id AS yubikeys_attribute_association_id,
                          yubikeys.id AS yubikeys_id,
                          yubikeys.prefix AS yubikeys_prefix,
                          yubikeys.enabled AS yubikeys_enabled
                     FROM yubikeys
               INNER JOIN user_yubikeys
                       ON user_yubikeys.yubikey_id = yubikeys.id
                    WHERE user_yubikeys.user_id = %s
                      AND yubikeys.prefix = %s"""
        self._execute(query, (user_id, token_id))
        return self._dictfetchone()

    #########################
    # YKVAL / YKSYNC QUERIES
    #########################
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
                'active': '1',
                'modified': -1,
                'yk_publicname': yk_publicname,
                'yk_counter': -1,
                'yk_use': -1,
                'yk_low': -1,
                'yk_high': -1,
                'nonce': '0000000000000000',
                'created': int(time.time())
            }
            # Key was missing in DB, adding it
            self.add_new_identity(local_params)
            logger.warning('[%s] Discovered new identity, creating yubikey', yk_publicname)
        logger.debug('[%s] Auth data: %s', yk_publicname, local_params)
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
        self._execute(query, identity)

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

    def read_queue(self):
        """
        Read all elements from queue
        """
        query = """SELECT server,
                          otp,
                          modified,
                          info,
                          server_nonce
                     FROM queue"""
        self._execute(query)
        return self._dictfetchall()

    def remove_from_queue(self, server, modified, server_nonce):
        """
        Remove a single element from queue
        """
        query = """DELETE FROM queue
                         WHERE server = %s
                           AND modified = %s
                           AND server_nonce = %s"""
        self._execute(query, (server, modified, server_nonce))

    def null_queue(self, server_nonce):
        """
        NULL queued_time for remaining entries in queue, to allow
        daemon to take care of them as soon as possible.
        """
        query = """UPDATE queue
                      SET queued = NULL
                    WHERE server_nonce = %s"""
        self._execute(query, (server_nonce,))

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
        self._execute(query, params)

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
        self._execute(query, (int(time.time()), otp_params['modified'],
                              otp_params['otp'], server, server_nonce, info))

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
        return self._dictfetchall()

    ################
    # YKKSM QUERIES
    ################
    def get_key_and_internalname(self, public_id):
        """
        Read token's AESkey and internalname for OTP decryption
        """
        query = """SELECT aeskey,
                          internalname
                     FROM yubikeys
                    WHERE (active = '1' OR active = 'true')
                      AND publicname = %s"""
        self._execute(query, (public_id,))
        return self._dictfetchone()
