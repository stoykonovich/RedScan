//strings
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
//networking
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <netinet/tcp.h>
#include <libnet.h>
//threads
#include <pthread.h>

char *target = NULL;
int port1 = 22;
int port2 = 80;
int port3 = 443;
int mode = 0;

int argparse(int argc, char *argv[]) {
    int opt;
    while((opt = getopt(argc, argv, "t:s:p:"))!=-1) {
        switch(opt) {
            case 't':
            target = optarg;
            mode = 1;
            break;
            case 's':
            target = optarg;
            mode = 2;
            break;
        }
    }
    return 0;
}

void normalscanning(){
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ping -4 -c 1 %s >/dev/null 2>&1", target);
    if(system(cmd)==0) {
        printf("[+] Target is alive, scanning...\n");
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        char banner[1024];
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        struct sockaddr_in scan1;
        scan1.sin_family = AF_INET;
        scan1.sin_port = htons(port1);
        inet_pton(AF_INET, target, &scan1.sin_addr);
        struct sockaddr_in scan2;
        scan1.sin_family = AF_INET;
        scan1.sin_port = htons(port2);
        inet_pton(AF_INET, target, &scan2.sin_addr);
        struct sockaddr_in scan3;
        scan1.sin_family = AF_INET;
        scan1.sin_port = htons(port3);
        inet_pton(AF_INET, target, &scan3.sin_addr);
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if(connect(sock, (struct sockaddr *)&scan1, sizeof(scan1))==0) {
            printf("[+] SSH is open\n");
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            read(sock, banner, sizeof(banner));
            printf("[+] %s detected\n",banner);
        } else{
            printf("SSH is closed\n");
        }
        if(connect(sock, (struct sockaddr *)&scan1, sizeof(scan2))==0) {
            printf("[+] HTTP webserver detected\n");
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            read(sock, banner, sizeof(banner));
            printf("[+] %s detected\n",banner);
        }
        if(connect(sock, (struct sockaddr *)&scan1, sizeof(scan3))==0) {
            printf("[+] HTTPS webserver detected\n");
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            read(sock, banner, sizeof(banner));
            printf("[+] %s detected\n",banner);
        }
        close(sock);
    }
}

int main(int argc, char *argv[]) {
    if(argparse(argc, argv)==0) {
        normalscanning();
    }
    return 0;
}