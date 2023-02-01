import sqlite3 as lite
import pyotp


class Database:

    def __init__(self):
        """
        setting up the interface that communicates with the database
        """
        self.dbPath = 'controller/test.db'
        self.con = lite.connect(self.dbPath)

    def query(self, sql):
        """
        function that execute sql query on the database
        :param sql: str - the sql query
        :return: list - list of the rows of the database
        """

        rows = []

        try:

            cur = self.con.cursor()
            cur.execute(sql)
            self.con.commit()
            rows = cur.fetchall()

        except lite.Error as e:
            print(f"sql error: {e}")

        return rows

    def create_table_if_not_exists(self, name, params):
        """
        creates table in the database if the table doesn't exist
        :param name: str - table name
        :param params: tuple (or any iterable) - table params
        :return: None
        """
        table_params = ",".join((param for param in params))
        query = f"CREATE TABLE IF NOT EXISTS {name} ({table_params})"

        self.query(query)

    def check_if_exists(self, name, params):
        """
        checking if data exists in the database
        :param name: str - table name
        :param params - data to check if exists
        :return: bool - exists or not
        """

        search_params = " AND ".join((param[0] + "=" + param[1] for param in params))
        query = f"SELECT * FROM {name} WHERE {search_params}"
        rows = self.query(query)

        return len(rows) != 0

    def add_user(self, email, password, name):
        """
        checking if the user can be added to the database and adding it
        :param email: str - user email
        :param password: str - user password
        :param name: str - user name
        :return: bool - added or not
        """

        self.create_table_if_not_exists("users", (
            "user_id INTEGER PRIMARY KEY AUTOINCREMENT", "email TEXT", "password TEXT", "secret TEXT"))

        if self.check_if_exists("users", (("email", f"'{email}'"),)):
            return False

        self.query(f"INSERT INTO users(email, password, name) VALUES('{email}', '{password}', '{name}')")
        return True

    def check_user_exists(self, email, password):
        """
        function that checks if user exists in the database
        :param email: str - user email
        :param password: str - user password
        :return: bool - exists or not
        """

        self.create_table_if_not_exists("users", (
            "user_id INTEGER PRIMARY KEY AUTOINCREMENT", "email TEXT", "password TEXT", "name TEXT"))

        return self.check_if_exists("users", (("email", f"'{email}'"), ("password", f"'{password}'")))

    def check_user_otp(self, email, otp):
        user = self.get_user_by_email(email)
        user_secret = user[3]

        totp = pyotp.TOTP(user_secret)

        return totp.verify(otp)

    def get_user_by_email(self, email):
        """
        returning user row by email
        :param email: str - user email
        :return: tuple - user row
        """

        return self.query(f"SELECT * FROM users WHERE email='{email}'")[0]

    def get_all_users(self):
        """
        return all users
        :return: list
        """

        return self.query(f"SELECT * FROM users")
