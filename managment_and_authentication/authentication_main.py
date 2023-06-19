from controllers.database import Database
from controllers.managment_authentication import AuthenticationManagement

if __name__ == '__main__':
    database = Database()
    server = AuthenticationManagement(database, "10.2.20.253", 12345)
    server.start()
