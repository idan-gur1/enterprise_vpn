import argparse
from models.database import Database
from controllers.managment_authentication import AuthenticationManagement

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Example script with argparse')

    parser.add_argument('--bind', dest="ip", metavar='ip', type=str, default='0.0.0.0',
                        help='ip address for the server to bind (default: 0.0.0.0)')
    parser.add_argument('--port', dest="port", metavar='port', type=int, default=8080,
                        help='Port number the server will run on (default: 12345)')

    args = parser.parse_args()

    database = Database('database.db')
    server = AuthenticationManagement(database, args.ip, args.port)
    server.start()
