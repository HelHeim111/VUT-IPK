# IPK Project 1: IPK Calculator Protocol

This project requires to implement a basic client which can communicate with server using both tcp and udp connection.
Client is specifiend for sending mathematical expression to server and reciving the result.

**Table of context**
1. [Language used](#language-used)
1. [License](#license)
1. [Usage](#usage)
1. [Examples of input and output](#examples-of-input-and-output)
1. [Implementation](#implementation)
1. [Testing](#testing)
1. [Used sources](#used-sources)

## **Language used**

- C++

## **License**
**MIT**

## **Usage**
Project is not multi-platform. It was tested on *NixOs*.
1. To start use a commnd **make** to compile the client.
1. After that start the client by typing in CMD command **./ipkcpc -h hostname -p port -m mode** where:
    - *hostname* is a IPv4 address of the server you want to connect.
    - *port* is a port of a server
    - *mode* is either tcp or udp
### Example
```bash
$make
$./ipkcpc -h 127.0.0.1 -p 2023 -m udp
```
Program can be stopped by CTRL+C. 
## **Examples of input and output**
### TCP
**Input**
```
HELLO
SOLVE (+ 1 2)
BYE
```
**Output**
```
HELLO
RESULT 3
BYE
```
### UDP
**Input**
```
(+ 1 2)
(a d c)
```
**Output**
```
OK:3
ERR:<error message>
```
---
## **Implementation**
### Establishing connection with the server
To make this are used several functions:
- *gethostbyname()* to get adress of the server
```cpp
server = gethostbyname(server_hostname)
```
- *socket()* to create client socket
```cpp
client_socket = socket(AF_INET, SOCK_STREAM, 0)
```
Also for tcp was used function *connect()*
```cpp
connect(client_socket, (const struct sockaddr *) &server_address, sizeof(server_address))
```
### Sending message to the server
For this are used functions *send()* for TCP
```cpp
send(client_socket, buf, strlen(buf), 0)
```
and *sendto()* for UDP
```cpp
sendto(client_socket, buf, BUFSIZE, 0, (struct sockaddr *) &server_address, serverlen)
```
### Reciving message from the server
As well as for sending the message, for this purpose are used 2 different functions for TCP and UDP.
- *recv* for TCP
```cpp
recv(client_socket, buf, BUFSIZE, 0)
```
- *recvfrom()* for UDP
```cpp
recvfrom(client_socket, buf, BUFSIZE, 0, (struct sockaddr *) &server_address, &serverlen)
```
### Handling *CTRL+C* event
For solving this problem is used function *signal()* from library *<signal.h>*. It calls function *event_handler*, which makes client to send message *"BYE"* to the server and end program.
```cpp
signal (SIGINT,event_handler);
```

```cpp
void event_handler(int sig) {
    bzero(buf, BUFSIZE);
    strcpy(buf, "BYE");
    event = true;
    return;
}
```
## **Testing**
After the program was finished, were held manual tests of the client. Results of tests are provided here:
- **TCP**
```bash
./ipkcpc -h 127.0.0.1 -p 2023 -m tcp
HELLO
HELLO
SOLVE (+ 7 3)
RESULT 10
SOLVE (- 2 5)
RESULT -3
SOLVE (* 7 9)
RESULT 63
^C
BYE
```
- **UDP**
```bash
./ipkcpc -h 127.0.0.1 -p 2023 -m udp
(+ 8 7)         
OK: 15
(- -3 -4)
OK: 1
(db a)
ERR:<error message>
(* 54 67)
OK: 3618
^C
```
## **Used sources**
1. [https://git.fit.vutbr.cz/NESFIT/IPK-Projekty/src/branch/master/Stubs/cpp](https://git.fit.vutbr.cz/NESFIT/IPK-Projekty/src/branch/master/Stubs/cpp)
1. [https://www.tutorialspoint.com/cplusplus/cpp_signal_handling.htm](https://www.tutorialspoint.com/cplusplus/cpp_signal_handling.htm)
1. [https://pubs.opengroup.org/onlinepubs/009604499/functions/socket.html](https://pubs.opengroup.org/onlinepubs/009604499/functions/socket.html)
1. [https://en.cppreference.com/w/c/program/signal](https://en.cppreference.com/w/c/program/signal)
1. [https://www.ibm.com/docs/en/zos/2.3.0?topic=functions-sendto-send-data-socket](https://www.ibm.com/docs/en/zos/2.3.0?topic=functions-sendto-send-data-socket)