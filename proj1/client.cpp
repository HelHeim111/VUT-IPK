#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <signal.h>

#define BUFSIZE 1024

char buf[BUFSIZE];
bool event = false;

/*
*   @brief     Function that handles the CTRL+C event
*   @params    int sig: the name of the signal that is recived    
*/
void event_handler(int sig) {
    bzero(buf, BUFSIZE);
    strcpy(buf, "BYE");
    event = true;
    return;
}

int main (int argc, const char * argv[]) {
	int client_socket, port_number, bytestx, bytesrx;
    socklen_t serverlen;
    const char *server_hostname;
    const char *mode;
    struct hostent *server;
    struct sockaddr_in server_address;

    /* Control of input paraments */
    if (argc != 7) {
       fprintf(stderr,"usage: %s -h <host> -p <port> -m <mode>\n", argv[0]);
       exit(EXIT_FAILURE);
    }
    server_hostname = argv[2];
    port_number = atoi(argv[4]);
    mode = argv[6];
    
    /* Getting the server adress*/
    
    if ((server = gethostbyname(server_hostname)) == NULL) {
        fprintf(stderr,"ERROR: no such host as %s\n", server_hostname);
        exit(EXIT_FAILURE);
    }
    
    /* Initing the server_adress structure*/
    bzero((char *) &server_address, sizeof(server_address));
    server_address.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&server_address.sin_addr.s_addr, server->h_length);
    server_address.sin_port = htons(port_number); 
    
	
    if(!strcmp(mode, "tcp")) {
        /* Creating socket */
        if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) <= 0)
        {
            perror("ERROR: socket");
            exit(EXIT_FAILURE);
        }        

        if (connect(client_socket, (const struct sockaddr *) &server_address, sizeof(server_address)) != 0)
        {
            perror("ERROR: connect");
            exit(EXIT_FAILURE);        
        }
        while(true) {
            
            bzero(buf, BUFSIZE);
            signal (SIGINT,event_handler); //calls event_handler(), when CTRL+C event is recived

            for(int i = 0; !event; i++) {
                if((buf[i] = getchar()) == '\n')
                    break;
            }
            

            /* sending message to the server*/
            bytestx = send(client_socket, buf, strlen(buf), 0);
            if (bytestx < 0) 
                perror("ERROR in sendto");
                
            bzero(buf, BUFSIZE);
            /* reciving an answer */
            bytesrx = recv(client_socket, buf, BUFSIZE, 0);
            if (bytesrx < 0) 
                perror("ERROR in recvfrom");
                
            printf("%s", buf);

            if(!strcmp(buf, "BYE\n")) {
                /*closing the socket and ending the program*/
                close(client_socket);
                return 0;
            }
                
        }
    }
    else if(!strcmp(mode, "udp")) {
        /* Creating socket */
        if ((client_socket = socket(AF_INET, SOCK_DGRAM, 0)) <= 0)
        {
            perror("ERROR: socket");
            exit(EXIT_FAILURE);
        }

        while(true) {  
            bzero(buf, BUFSIZE);
            /*Writing message into buffer due to requirements*/
            int buf_len = 0;         
            for(int i = 2;; i++) {
                ++buf_len;
                if((buf[i] = getchar()) == '\n')
                    break;
                
            }
            buf[0] = '\0';
            buf[1] = buf_len;
            buf[buf_len + 1] = '\0';
            
            /* sending message to the server*/
            serverlen = sizeof(server_address);
            bytestx = sendto(client_socket, buf, 255, 0, (struct sockaddr *) &server_address, serverlen);
            if (bytestx < 0) 
                perror("ERROR: sendto");
            bzero(buf, BUFSIZE);   
            /* reciving an answer */
            
            bytesrx = recvfrom(client_socket, buf, 255, 0, (struct sockaddr *) &server_address, &serverlen);
            
            if (bytesrx < 0) 
                perror("ERROR: recvfrom");
            if(buf[1] == '\0')
                printf("OK: %s\n", &buf[3]);
            else
                printf("ERR:<error message>\n");

        }
    }
    
}
