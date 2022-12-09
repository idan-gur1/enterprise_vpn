import socket
from ssl import SSLContext, PROTOCOL_TLS_SERVER

HOST = "127.0.0.1"
PORT = 60000

ssl_context = SSLContext(PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain('ssl_cert/cert.pem', 'ssl_cert/key.key')

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server = ssl_context.wrap_socket(server, server_side=True)

server.bind((HOST, PORT))
server.listen(0)

connection, client_address = server.accept()
while True:
    data = connection.recv(1024)
    if not data:
        connection.close()
        break
    print(f"Received: {data}")
    connection.send('got'.encode())

server.close()