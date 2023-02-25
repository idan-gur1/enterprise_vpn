from controllers.database import Database
from controllers.managment_authentication import AuthenticationManagement

if __name__ == '__main__':
    database = Database()
    server = AuthenticationManagement(database, "0.0.0.0", 55555)
    server.start()
