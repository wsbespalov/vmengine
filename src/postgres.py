import psycopg2


class PostgresHelper(object):

    def __init__(self, *args, **kwargs):
        self.config = kwargs.get('config', dict())
        self.database = self.config.get('database', 'postgres')
        self.user = self.config.get('user', 'postgres')
        self.password = self.config.get('password', '123')
        self.host = self.config.get('host', '127.0.0.1')
        self.port = self.config.get('port', '5432')
        self.connection = None
        self.cursor = None

    def connect(self):
        self.connection = psycopg2.connect(
            database=self.database,
            user=self.user,
            password=self.password,
            host=self.host,
            port=self.port
        )
        self.cursor = self.connection.cursor()

    def disconnect(self):
        if self.connection is not None:
            self.connection.close()
        self.connection = None
        self.cursor = None

    def insert_cves_record(self, id=None):
        if self.connection is not None:
            if self.cursor is not None:
                if id is not None:
                    self.cursor.execute(
                        '''
                        INSERT INTO CVES (_ID, ID) \
                        VALUES (DEFAULT, '%s');
                        ''' % id
                    )
                    self.connection.commit()

    def insert_cves_list_of_records(self, list_of_records=None):
        if list_of_records:
            for record in list_of_records:
                self.insert_cves_record(record.get("ID", "undefined"))

    def create_cves_table(self):
        if self.connection is not None:
            self.cursor.execute(
                '''CREATE TABLE IF NOT EXISTS CVES
                (
                    _ID SERIAL PRIMARY KEY NOT NULL,
                    ID TEXT
                );
                '''
            )
            self.connection.commit()

    def delete_cves_table(self):
        if self.connection is not None:
            self.cursor.execute(
                '''
                DROP TABLE IF EXISTS CVES;
                '''
            )

    def select_cves_table(self):
        if self.connection is not None:
            self.cursor.execute(
                '''SELECT _ID, ID FROM CVES;
                '''
            )
            rows = self.cursor.fetchall()
            for row in rows:
                print("_ID = {}".format(row[0]))
                print(" ID = {}".format(row[1]))

p = PostgresHelper()
p.connect()
p.delete_cves_table()
p.create_cves_table()
p.insert_cves_record("CVE-2018-00000")
p.insert_cves_list_of_records([{"ID": "CVE-2018-00001"}, {"ID": "CVE-2018-00002"}, {"ID": "CVE-2018-00003"}])
p.select_cves_table()
p.disconnect()