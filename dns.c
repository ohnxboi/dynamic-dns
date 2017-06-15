/* 
 * dns.c - a simple DNS replier
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <limits.h>
#include <arpa/inet.h>
#include <stdint.h>
#include "miscutil.h"
#include "dns_parse.h"

#define BUFSIZE 65535
#define MONITOR_FILE "/var/www/ignacio_ip.txt"

#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define EVENT_BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )

struct __attribute__((__packed__)) dns_answer_a {
    struct dns_answer header;
    unsigned int address;
};

void make_response_bytes_for_a(void *inptr, unsigned int ipaddr) {
    struct dns_answer_a *resp = (struct dns_answer_a *)inptr;
    resp->header.name = htons((unsigned short)0xc00c); // endian swapped already
    resp->header.type = htons((unsigned short)DNS_RECORD_A); // endian swapped already
    resp->header.class = htons((unsigned short)0x0001); // endian swapped already
    resp->header.ttl = htonl(0x0000012b); // not sure how to endian swap
    resp->header.dlen = htons((unsigned short)0x0004); // endian swapped
    
    resp->address = htonl(ipaddr); //
}

void make_response_bytes_for_txt(void *inptr, unsigned char *text, unsigned short textlength) {
    struct dns_answer *resp = (struct dns_answer *)inptr;
    unsigned char *tmp;
    unsigned short i;
    
    resp->name = htons((unsigned short)0xc00c); // endian swapped already
    resp->type = htons((unsigned short)DNS_RECORD_TXT); // endian swapped already
    resp->class = htons((unsigned short)0x0001); // endian swapped already
    resp->ttl = htonl(0x0000012b); // not sure how to endian swap
    resp->dlen = htons((unsigned short)textlength); // endian swapped
    
    tmp = (unsigned char *)(&(resp->dlen)) + 2; // skip past short
    
    for (i = 0; i < textlength; i++) {
        tmp[i] = text[i]; // when copying byte-for-byte, no endian trickery needed
    }
}

static int *IGNACIO_IP_PTR; /* pointer to ignacio's ip */

int update_ignacio_ip(const char *fname) {
    FILE *f = fopen(fname, "rb");
    
    if (f == NULL) {
        printf("Oops could not open file :( Setting ip to 0\n");
        return 0;
    }
    
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);  //same as rewind(f);

    char *ipstuff = malloc(fsize + 1);
    
    if (!ipstuff) {
        printf("Big Oops could not allocate memory!!!! :(((( Setting ip to 0\n");
        return 0;
    }
    
    fread(ipstuff, fsize, 1, f);
    fclose(f);
    ipstuff[fsize] = 0;
    
    char *ipdata = ipstuff, *ipdata2;
    while (*ipdata != '\n' && *ipdata != '\0') ipdata++; // skip past first newline
    ipdata++;
    ipdata2 = ipdata;
    while (*ipdata2 != '\n' && *ipdata2 != '\0') ipdata2++; // skip past second newline
    *ipdata2 = '\0';
    printf("Read string IP of %s from file! :)\n", ipdata);
    int ip;
    inet_pton(AF_INET, ipdata, &ip);
    free(ipstuff);
    return htonl(ip);
}

 #define BUF_LEN (10 * (sizeof(struct inotify_event) + NAME_MAX + 1))


void monitorstuff() {
    int inotifyFd, wd, j;
    char buf[BUF_LEN] __attribute__ ((aligned(8)));
    ssize_t numRead;
    char *p;
    struct inotify_event *event;

    inotifyFd = inotify_init();                 /* Create inotify instance */
    if (inotifyFd == -1) printf("ERROR: FAILED TO INITIALIZE INOTIFY!!!\n");
 
    /* For each command-line argument, add a watch for all events */
    inotify_add_watch(inotifyFd, MONITOR_FILE, IN_MODIFY);
    if (wd == -1) printf("ERROR: FAILED TO WATCH FILE INOTIFY!!!\n");
    printf("Watching %s using wd %d\n", MONITOR_FILE, wd);

    for (;;) {                                  /* Read events forever */
        numRead = read(inotifyFd, buf, BUF_LEN);
        if (numRead == 0) puts("read() from inotify fd returned 0!");
 
        if (numRead == -1) puts("read() FAILED!!!");
 
        printf("--------------------\nRead %ld bytes from inotify fd\n", (long) numRead);
 
        /* Process all of the events in buffer returned by read() */
 
        for (p = buf; p < buf + numRead; ) {
            event = (struct inotify_event *) p;
            
            if (event->mask & IN_MODIFY) {
                puts("Attempting to update ignacio ip! :D");
                update_ignacio_ip(MONITOR_FILE);
            }
 
            p += sizeof(struct inotify_event) + event->len;
        }
        
        puts("--------------------------------");
    }
}


int main(int argc, char **argv) {
    int sockfd; /* socket */
    int portno; /* port to listen on */
    int clientlen; /* byte size of client's address */
    struct sockaddr_in serveraddr; /* server's addr */
    struct sockaddr_in clientaddr; /* client addr */
    struct hostent *hostp; /* client host info */
    unsigned char buf[BUFSIZE]; /* message buf */
    char *hostaddrp; /* dotted decimal host addr string */
    int optval; /* flag value for setsockopt */
    int n; /* message byte size */
    
    IGNACIO_IP_PTR = mmap(NULL, sizeof *IGNACIO_IP_PTR, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    
    if (fork() == 0) {
        /* watch file  */
        *IGNACIO_IP_PTR = update_ignacio_ip(MONITOR_FILE);
        monitorstuff();
        printf("CRAP WE SHOULD NEVER GET HERE!!!!!!\n");
        exit(-1);
    }
    
    // do DNS stufff
    
    // self dns stuff
    struct dns_request *test;
    unsigned char *tmp;
    char *temp;
    unsigned short *code;
    int i, offset;
    
    /* 
    * check command line arguments 
    */
    if (argc != 2 && argc != 3) {
        fprintf(stderr, "usage: %s <port> [input file]\n", argv[0]);
        exit(1);
    }
    
    portno = atoi(argv[1]);
    
    if (argc == 3) {
        printf("Warning: DNS from file not yet implemented\n");
    }
    
    /* 
    * socket: create the parent socket 
    */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) error("ERROR opening socket");
    
    printf("socket open\n");
    
    /* setsockopt: Handy debugging trick that lets 
    * us rerun the server immediately after we kill it; 
    * otherwise we have to wait about 20 secs. 
    * Eliminates "ERROR on binding: Address already in use" error. 
    */
    optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
        (const void *)&optval , sizeof(int));
    
    /*
    * build the server's Internet address
    */
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons((unsigned short)portno);
    
    /* 
    * bind: associate the parent socket with a port 
    */
    if (bind(sockfd, (struct sockaddr *) &serveraddr, 
        sizeof(serveraddr)) < 0) 
        error("ERROR on binding");
    
    printf("bound socket to port\n");
    
    /* 
    * main loop: wait for a datagram, then echo it
    */
    printf("started listening!\n");
    clientlen = sizeof(clientaddr);
    while (1) {
        /*
        * recvfrom: receive a UDP datagram from a client
        */
        bzero(buf, BUFSIZE);
        n = recvfrom(sockfd, buf, BUFSIZE, 0,
            (struct sockaddr *) &clientaddr, &clientlen);
        printf("------------------\n");
        if (n < 0) error("ERROR in recvfrom");
        
        /* 
        * gethostbyaddr: determine who sent the datagram
        */
        hostp = gethostbyaddr((const char *)&clientaddr.sin_addr.s_addr, 
                sizeof(clientaddr.sin_addr.s_addr), AF_INET);
        
        hostaddrp = inet_ntoa(clientaddr.sin_addr);
        if (hostaddrp == NULL) error("ERROR on inet_ntoa\n");
        
        printf("server received %d byte datagram from %s\n", n, hostaddrp);
        hexDump("recv data", buf, n);
        
        test = (struct dns_request *)buf;
        (test->header).num_questions = ntohs((test->header).num_questions);
        (test->header).num_answers = ntohs((test->header).num_answers);
        
        printf("\tExtracted data: \n");
        printf("\t\tTransaction ID: %hu\n", (test->header).transaction_id);
        printf("\t\tNumber of questions: %hu\n", (test->header).num_questions);
        
        temp = NULL;
        tmp = &(test->data);
        
        for (i = 0; i < (test->header).num_questions; i++) {
            free(temp);
            
            if (tmp - buf > BUFSIZE) { // prevent buffer overflow
                printf("Advanced too much! Malformed packet or possible attack attempt.\n");
                break;
            }
            
            temp = dns_str_convert(tmp);
            printf("\t\tQuery #%d:\n", i+1);
            printf("\t\t\t%s\n", temp);
            offset = strlen(temp) + 1;
            
            code = (unsigned short *)((unsigned char *)tmp + offset);
            *code = ntohs(*code);
            
            printf("\t\t\tType: %s", code_to_str(*code));
            if (*code_to_str(*code) == 'U') printf(" (code %hu)", *code);
            
            tmp += offset + 2 + 2;
            
            puts("");
        }
        
        if (buf[2] & 0x80 || (test->header).num_answers > 0) {
            printf("Weirdly enough, this packet contains an answer.\nJumping out.");
            goto nextOne;
        }
        
        if ((test->header).num_questions == 1) {
            unsigned char *myNewBytes;
            int ip4;
            switch (*code) {
                case DNS_RECORD_ANY:
                case DNS_RECORD_A:
                    printf("Replying!\n");
                    n = 16 + strlen(temp) + 1;
                    
                    // copy memory + response stub for A
                    myNewBytes = calloc(n+sizeof(struct dns_answer_a), sizeof(unsigned char));
                    test = (struct dns_request *)myNewBytes;
                    
                    // switch back to endian-swapped code
                    *code = htons(*code);
                    
                    // copy old stuff
                    memcpy(myNewBytes, buf, n);
                    
                    // format the header
                    (test->header).flags = htons(0x8400); // standard response, no error (endian-swapped) - don't recursively query
                    // questions # is the same
                    (test->header).num_answers = htons(0x0001);
                    (test->header).num_questions = htons(0x0001);
                    (test->header).num_authority = 0;
                    (test->header).num_additional = 0;
                    
                    ip4 = *IGNACIO_IP_PTR;
                    
                    // throwin the ip response at the right spot
                    make_response_bytes_for_a(myNewBytes+n, ip4);
            
                    // for ip response
                    n += sizeof(struct dns_answer_a);
                    
                    // make_response_bytes_for_ip
                    hexDump("send data", myNewBytes, n);
                    
                    n = sendto(sockfd, myNewBytes, n, 0, (struct sockaddr *) &clientaddr, clientlen);
                    if (n < 0) printf("Failed to reply.\n");
                    free(myNewBytes);
                    break;
                case DNS_RECORD_TXT: // these don't work right now
                    printf("Replying!\n");
                    n = 16 + strlen(temp) + 1;
                    
                    char *response = "\006o/ hai\037this is ohnx's DNS responder :)\052for more info, please visit d.masonx.ca :p";
                    int resplen = strlen(response);
                    
                    // copy memory + response stub for TXT
                    myNewBytes = calloc(n+sizeof(struct dns_answer) + resplen, sizeof(unsigned char));
                    test = (struct dns_request *)myNewBytes;
                    
                    // switch back to endian-swapped code
                    *code = htons(*code);
                    
                    // copy old stuff
                    memcpy(myNewBytes, buf, n);
                    
                    // format the header
                    (test->header).flags = htons(0x8000); // standard response, no error (endian-swapped) - don't recursively query
                    // questions # is the same
                    (test->header).num_answers = htons(0x0001);
                    (test->header).num_questions = htons(0x0001);
                    (test->header).num_authority = 0;
                    (test->header).num_additional = 0;
                    
                    // throwin the ip response at the right spot
                    make_response_bytes_for_txt(myNewBytes+n, response, (unsigned short)resplen);
            
                    // for ip response
                    n += sizeof(struct dns_answer) + resplen;
                    
                    // make_response_bytes_for_ip
                    hexDump("send data", myNewBytes, n);
                    
                    n = sendto(sockfd, myNewBytes, n, 0, (struct sockaddr *) &clientaddr, clientlen);
                    if (n < 0) printf("Failed to reply.\n");
                    free(myNewBytes);
                    break;
                default:
                    goto error_message;
            }
            free(temp);
            temp = NULL;
            goto nextOne;
        }

        error_message:
        // send no answers
        printf("Replying Error!\n");
        
        // switch back to endian-swapped code
        *code = htons(*code);
        
        // format the header
        (test->header).flags = htons(0x8003); // standard response, not found error (endian-swapped) - don't recursively query
        // questions # is the same
        (test->header).num_answers = 0;
        (test->header).num_questions = htons(0x0001);
        (test->header).num_authority = 0;
        (test->header).num_additional = 0;
        
        // make_response_bytes_for_ip
        hexDump("send data", buf, n);
        
        n = sendto(sockfd, buf, n, 0, (struct sockaddr *) &clientaddr, clientlen);
        if (n < 0) printf("Failed to reply.\n");
        
        nextOne:
        free(temp);
        temp = NULL;
    }
}
