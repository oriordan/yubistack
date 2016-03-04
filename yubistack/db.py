"""
ykval.db
~~~~~~~~

Database Handler
"""

import logging

from .config import settings

logger = logging.getLogger(__name__)

class DBHandler(object):
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
        logger.debug('QUERY: %s PARAMS: %s', query, params)
        try:
            rowcount = self.cursor.execute(query, params)
            self._db.commit()
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
