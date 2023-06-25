# Enterprise VPN Project

This project aims to develop a robust and secure enterprise-level VPN solution. The VPN provides a range of features and functionalities as described below.

## Features

The Enterprise VPN project incorporates the following key features:

- **Encryption Between Clients:** The VPN ensures that all communication between clients is encrypted, protecting sensitive data from unauthorized access. It encrypts the data with an AES encryption algorithm, and the server exchange the key securely with the clients with the use of rsa asymmetric encryption.

- **Remote Access to Network:** Employees or authorized users can securely access the enterprise network from remote locations using the VPN. This allows them to connect to internal resources, such as shared drives, applications, and databases as if they were physically present within the office network. The VPN achieves this by tunneling the packets that are designated to a private network that is not the host's network. 

- **Proxy and File Server:** The VPN project includes a proxy server that acts as an intermediary between clients and the internet. It helps enforce security policies and filter websites. Additionally, a file server is included that allows secure file sharing and collaboration among authorized users within the enterprise network.

- **System Administration:** The VPN project provides administrative capabilities to manage the VPN infrastructure effectively. System administrators can monitor and control VPN connections, manage user access privileges, and configure security settings.

## Deployment

To get started with the  VPN, follow the steps below:

1. **Requirements:** Review and download the VPN requirements with the requirements.txt file and pip.

2. **Management and Authentication Server Setup:** start the management server by navigating to the management_and_authentication folder and executing the following command in the terminal: <br> `python authentication_main.py --bind <IP_ADDRESS> --port <PORT_NUMBER>` <br> once activated the server prints the initial admin credentials.

3. **Remote Access Server Setup:** start the remote access server by navigating to the outer_user_manager folder and executing the following command in the terminal: <br> `python outer_user_manager_divert.py --bind <IP_ADDRESS> --port <PORT_NUMBER> <AUTH_SERVER_IP_ADDRESS>:<AUTH_SERVER_PORT_NUMBER>`

4. **Proxy Server Setup:** Start the proxy server by navigating to the proxy folder and executing the following command in the terminal: <br> `python Proxy_Server.py --bind <IP_ADDRESS> <AUTH_SERVER_IP_ADDRESS>:<AUTH_SERVER_PORT_NUMBER>`

5. **File Server Setup:** Start the file server by navigating to the file server folder and executing the following command in the terminal: <br> `python file_sever.py --bind <IP_ADDRESS> <AUTH_SERVER_IP_ADDRESS>:<AUTH_SERVER_PORT_NUMBER>`

6. **Client configuration and setup:** Configure the client by first navigating to the configuration file inside the client folder. inside the config file change the `main_auth_ip` field to the IP address of the management server along with the `main_auth_port`, `client_ip`, and `interface` to their corresponding values (Note: the value of the `interface` field is the index of the NIC corresponding to the `client_ip` field).<br>After configuring the client, start the client by executing the following command in the terminal:<br>`python client_main.py`


**Note:** This Enterprise VPN Project is developed solely for educational purposes and should not be used in a production environment or for commercial purposes. It serves as a learning tool to understand the concepts and implementation of a secure VPN solution. While efforts have been made to ensure the security and functionality of the project, it may not meet the stringent requirements necessary for real-world production or commercial use.
