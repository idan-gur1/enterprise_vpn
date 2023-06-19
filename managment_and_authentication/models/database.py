import sqlite3 as lite
import pyotp


class Database:

    def __init__(self, db_path='test.db'):
        """
        setting up the interface that communicates with the database
        """
        self.db_path = db_path
        self.con = lite.connect(self.db_path)
        # #### for debugging
        self.create_table_if_not_exists("users", (
            "user_id INTEGER PRIMARY KEY AUTOINCREMENT", "email TEXT", "password TEXT", "secret TEXT", "admin INTEGER"))
        print(self.add_user("test@test.com", "asdasdasd", True))
        print(self.add_user("test2@test.com", "asdasdasd"))
        print(self.add_user("test3@test.com", "asdasdasd"))
        print(self.get_all_users())
        #####

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

    def add_user(self, email, password, admin=False):
        """
        checking if the user can be added to the database and adding it
        :param email: str - user email
        :param password: str - user password
        :param admin: bool - user admin or not
        :return: bool/str - if added then secret str if not then False
        """

        self.create_table_if_not_exists("users", (
            "user_id INTEGER PRIMARY KEY AUTOINCREMENT", "email TEXT", "password TEXT", "secret TEXT", "admin INTEGER"))

        if self.check_if_exists("users", (("email", f"'{email}'"),)):
            return False

        secret = pyotp.random_base32()

        self.query(f"INSERT INTO users(email, password, secret, admin) VALUES('{email}', '{password}', '{secret}', {str(1) if admin else str(0)})")
        return secret

    def remove_user(self, email):
        """
        function that removes a user from the users table by the email
        :param email: str - user email
        :return: None
        """
        self.create_table_if_not_exists("users", (
            "user_id INTEGER PRIMARY KEY AUTOINCREMENT", "email TEXT", "password TEXT", "secret TEXT", "admin INTEGER"))

        self.query(f"DELETE FROM users WHERE email='{email}'")

    def check_user_exists(self, email, password):
        """
        function that checks if user exists in the database
        :param email: str - user email
        :param password: str - user password
        :return: bool - exists or not
        """

        self.create_table_if_not_exists("users", (
            "user_id INTEGER PRIMARY KEY AUTOINCREMENT", "email TEXT", "password TEXT", "secret TEXT", "admin INTEGER"))

        return self.check_if_exists("users", (("email", f"'{email}'"), ("password", f"'{password}'")))

    def check_if_admin(self, email):
        """
        function that checks if user is admin in the database
        :param email: str - user email
        :return: bool - admin or not
        """

        user_row = self.get_user_by_email(email)
        return user_row[4] == 1

    def check_user_otp(self, email, otp):
        user = self.get_user_by_email(email)
        user_secret = user[3]

        totp = pyotp.TOTP(user_secret)

        return totp.verify(otp)

    def change_admin_status(self, email):
        """
        function that changes the admin status of a user - admin -> not admin, and vice versa
        :param email: str -
        :return:
        """

        if not self.check_if_exists("users", (("email", f"'{email}'"),)):
            return False

        new_admin_value = "0" if self.check_if_admin(email) else "1"
        print(new_admin_value)
        self.query(f"UPDATE users SET admin={new_admin_value} WHERE email='{email}'")

        return True

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
