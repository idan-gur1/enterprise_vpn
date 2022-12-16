
# >>> import socket
# >>> socket.inet_aton('115.255.8.97')
# b's\xff\x08a'
# >>> _
# b's\xff\x08a'
# >>> _
# b's\xff\x08a'
# >>> binascii.hexlify(_).upper()
# b'73FF0861'
# >>> binascii.unhexlify(b'73FF0861')
# b's\xff\x08a'
# >>> socket.inet_ntoa(b's\xff\x08a')
# '115.255.8.97'