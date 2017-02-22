/**
 * Copyright (C) 2012 Analog Devices, Inc.
 *
 * Modified by PolyVection to work with ADAU1451 and SigmaStudio 3.14
 *
 * THIS SOFTWARE IS PROVIDED BY ANALOG DEVICES "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, NON-INFRINGEMENT,
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *
 **/
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdbool.h>
#include <time.h>

#include "sigma_tcp.h"

#include <netinet/in.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>

void delay(int milliseconds)
{
    long pause;
    clock_t now,then;

    pause = milliseconds*(CLOCKS_PER_SEC/1000);
    now = then = clock();
    while( (now-then) < pause )
        now = clock();
}

static void printArray(uint8_t *a, int skip, int len) {
    for (int i = skip; i < skip+len; i++){
	 printf("p[%d]: %02x ", i,a[i]);
	}
}

//#define printArray(arr) printArray_((arr), sizeof(arr)/sizeof(arr[0]))

static void addr_to_str(const struct sockaddr *sa, char *s, size_t maxlen)
{
	switch(sa->sa_family) {
	case AF_INET:
		inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
				s, maxlen);
		break;
	case AF_INET6:
		inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
				s, maxlen);
	break;
	default:
		strncpy(s, "Unkown", maxlen);
	}
}

static int show_addrs(int sck)
{
	char buf[256];
	char ip[INET6_ADDRSTRLEN];
	struct ifconf ifc;
	struct ifreq *ifr;
	unsigned int i, n;
	int ret;

	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	ret = ioctl(sck, SIOCGIFCONF, &ifc);
	if (ret < 0) {
		perror("ioctl(SIOCGIFCONF)");
		return 1;
	}

	ifr = ifc.ifc_req;
	n = ifc.ifc_len / sizeof(struct ifreq);

	printf("IP addresses:\n");

	for (i = 0; i < n; i++) {
		struct sockaddr *addr = &ifr[i].ifr_addr;

		if (strcmp(ifr[i].ifr_name, "lo") == 0)
			continue;

		addr_to_str(addr, ip, INET6_ADDRSTRLEN);
		printf("%s: %s\n", &ifr[i].ifr_name, ip);
	}

	return 0;
}

#define COMMAND_READ 0x0a
#define COMMAND_WRITE 0x0b

static uint8_t debug_data[256];

static int debug_read(unsigned int addr, unsigned int len, uint8_t *data)
{
	if (addr < 0x4000 || addr + len > 0x4100) {
		memset(data, 0x00, len);
		return 0;
	}

	printf("read: %.2x %d\n", addr, len);

	addr -= 0x4000;
	memcpy(data, debug_data + addr, len);

	return 0;
}

static int debug_write(unsigned int addr, unsigned int len, const uint8_t *data)
{
	if (addr < 0x4000 || addr + len > 0x4100)
		return 0;

	printf("write: %.2x %d\n", addr, len);

	addr -= 0x4000;
	memcpy(debug_data + addr, data, len);

	return 0;
}

static const struct backend_ops debug_backend_ops = {
	.read = debug_read,
	.write = debug_write,
};

static const struct backend_ops *backend_ops = &debug_backend_ops;

static void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
		return &(((struct sockaddr_in*)sa)->sin_addr);

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

static void handle_connection(int fd)
{
	uint8_t *buf;
	size_t buf_size;
	uint8_t *p = buf;
	uint8_t *data;
	unsigned int addr, addr_H, addr_L;
	unsigned int total_len, data_len;
	int count, count_old, ret, skip; 

	count = 0;
	count_old=0;
	skip=0;

	buf_size = 1024;
	buf = malloc(buf_size);
	p = malloc(buf_size); 
	if (!buf)
		goto exit;

	while (1) {
		//memmove(buf, p, buf_size);
		//p = buf;
		int b = 0;
		for (int i = count; i > -1; i--){
			//memmove(p[ret-i], p[b], 1);
			p[b] = p[count_old-i];
			b++;
		}   

		printf("\n############################\n");                            
                printf("############################\n");                                   
                printf("NEW DATA COMING IN!\n");                                   
                printf("############################\n");                                   
                printf("############################\n");   

		printf("\n");
		printf("buf_size: %d\n", buf_size);
		printf("count: %d\n", count); 
		printf("read count: %d\n", buf_size - count);
		ret = read(fd, p + count, buf_size - count);

		printf("bytes read: %d\n", ret);
		if (ret <= 0)
			break;	

		
		//p = buf;
		count_old = count + ret;
		count += ret;
		skip=0;		
		//printf("Printing whole p: \n");
		//printArray(p,0,256);
		//printf("\nEND OF DATA\n");
		printf("\n");    
		printf("\n");
		//printf("%" PRIu8 "\n", p);
		
		if (ret > 0){
			for (int i = 0; i < ret; i+=14){ 
				//printf("CMD[%d]= %02x; ", i,p[i]);               
                                               
                	}
		};  
		
		printf("\n");




		while (count > 13) {

			if (p[0+skip] == COMMAND_READ){				
				
				total_len 	= p[4+skip];
				data_len	= p[9+skip];
				data		= (p[12+skip] << 8) | p[13+skip];
				addr		= (p[10+skip] << 8) | p[11+skip];
				addr_H		= p[10+skip];
				addr_L		= p[11+skip];
				skip		= skip + total_len;
				count	        = count - total_len;

				//printf("\nDETECTED READ CMD\n");
				//printf("ACTUAL SKIP: %d\n", skip);
				//printf("ACTUAL COUNT: %d\n", count); 
				//printf("TOTAL MSG LENGTH IS: %d\n", total_len);
				//printf("TOTAL DATA LENGTH IS: %d\n", data_len);
				printf("ADDRESS IS: %04x\n", addr);
				//printf("DATA IS: %04x\n", data);
				
				buf[0] = COMMAND_WRITE;
				//buf[1] = (0x4 + data_len) >> 8;
				//buf[2] = 0x02;//(0x4 + data_len) & 0xff;
				//buf[3] = backend_ops->read(addr, data_len, buf + 4);
				buf[1] = 0x00;
				buf[2] = 0x00;
				buf[3] = 0x00;
				buf[4] = 0x00;
				buf[5] = 0x00;
				buf[6] = 0x10;
				buf[7] = 0x01;
				buf[8] = 0x00;
				buf[9] = 0x02;
				buf[10] = addr_H;
				buf[11] = addr_L;
				buf[12] = 0x00;
				buf[13] = backend_ops->read(addr, data_len, buf + 14);
                                //delay(100);
				//buf[14] = backend_ops->read(addr, data_len, buf + 14);
				//printf("BUF14: %02x", buf[14]);   
				//printf("BUF15: %02x", buf[15]);
				//printf("BUF16: %02x", buf[16]);   
				//printf("DATA READ IS: %02x %02x\n", buf[14], buf[15]); 
				//printf("SENDING: \n");
				//printArray(buf,0,16);
				//printf("\n");
				write(fd, buf, 16);  
				//write(fd, buf, 4 + data_len);	
							
			} else {
				
				total_len       =(p[5+skip] << 8) | p[6+skip];// p[6+skip];                    
                                data_len        = (p[10+skip] << 8) | p[11+skip];//p[11+skip];                    
                                data            = (p[14+skip] << 8) | p[15+skip];
                                data_H		= p[14+skip];
				data_L		= p[15+skip];
				addr            = (p[12+skip] << 8) | p[13+skip];
                                addr_H          = p[12+skip];                   
                                addr_L          = p[13+skip];                   
                                //skip            = skip + total_len;             
                                //count           = count - total_len; 
				//buf[0] = COMMAND_WRITE;
				//buf[1] = data_H;
				//buf[2] = data_L;
				int e = 0;
				for(int i = 14; i<total_len; i++){
					buf[e] = p[i+skip];
					printf("buf[%d] = p [%d+%d] =  %02x\n", e, i,skip,p[i+skip]);
					e++;
				}
				skip            = skip + total_len;                                       
                                count           = count - total_len;

				printf("WRITE TO: %04x DATA: ", addr);
				// printf("DATA_H: %02x\n", data_H);
				//printf("DATA_L: %02x\n", data_L); 
				printArray(buf,0,data_len); 
				printf("\n\n");
				backend_ops->write(addr, data_len, buf);	
			}
			
		}
	}

exit:
	free(buf);
}

int main(int argc, char *argv[])
{
    int sockfd, new_fd;
	struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr;
    socklen_t sin_size;
    struct sigaction sa;
    int reuse = 1;
    char s[INET6_ADDRSTRLEN];
    int ret;

	if (argc >= 2) {
		if (strcmp(argv[1], "debug") == 0)
			backend_ops = &debug_backend_ops;
		else if (strcmp(argv[1], "i2c") == 0)
			backend_ops = &i2c_backend_ops;
		else if (strcmp(argv[1], "regmap") == 0)
			backend_ops = &regmap_backend_ops;
		else {
			printf("Usage: %s <backend> <backend arg0> ...\n"
				   "Available backends: debug, i2c, regmap\n", argv[0]);
			exit(0);
		}

		printf("Using %s backend\n", argv[1]);
	}

	if (backend_ops->open) {
		ret = backend_ops->open(argc, argv);
		if (ret)
			exit(1);
	}

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

	ret = getaddrinfo(NULL, "8086", &hints, &servinfo);
    if (ret != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        return 1;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse,
                sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    if (p == NULL)  {
        fprintf(stderr, "Failed to bind\n");
        return 2;
    }

    freeaddrinfo(servinfo);

    if (listen(sockfd, 0) == -1) {
        perror("listen");
        exit(1);
    }

    printf("Waiting for connections...\n");
	show_addrs(sockfd);

    while (true) {
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1) {
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family,
            get_in_addr((struct sockaddr *)&their_addr),
            s, sizeof s);

        printf("New connection from %s\n", s);
		handle_connection(new_fd);
        printf("Connection closed\n");
    }

    return 0;
}
