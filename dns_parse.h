#ifndef DNS_PARSE_H
#define DNS_PARSE_H
#include <string.h>
#include <stdlib.h>

struct __attribute__((__packed__)) dns_header {
    // transaction id 2 bytes
    unsigned short transaction_id;
    
    // flags
    //x....... ........ = Response
    //.xxxx... ........ = Opcode
    //......x. ........ = Truncated
    //.......x ........ = Recursion desired
    //........ .x...... = Z: reserved (0)
    //........ ...x.... = Non-authenticated data OK
    unsigned short flags;
    
    // # of questions
    unsigned short num_questions;
    
    // # of answers
    unsigned short num_answers;
    
    // # authorities
    unsigned short num_authority;
    
    // # additional stuff
    unsigned short num_additional;
    
    // questions/answers/etc. follow...
};

struct __attribute__((__packed__)) dns_request {
    struct dns_header header;
    unsigned char data;
};

enum dns_record_type {
    DNS_RECORD_A = 1,
    DNS_RECORD_NS = 2,
    DNS_RECORD_CNAME = 5,
    DNS_RECORD_SOA = 6,
    DNS_RECORD_PTR = 12,
    DNS_RECORD_MX = 15,
    DNS_RECORD_TXT = 16,
    DNS_RECORD_AAAA = 28,
    DNS_RECORD_SRV = 33,
    DNS_RECORD_RRSIG = 46,
    DNS_RECORD_ANY = 255,
};

struct __attribute__((__packed__)) dns_answer {
    unsigned short name;
    unsigned short type;
    unsigned short class;
    unsigned int ttl;
    unsigned short dlen;
    /* data here */
};

const char *code_to_str(enum dns_record_type in);
char *dns_str_convert(void *in);
void *str_dns_convert(unsigned char *in);

#endif /* DNS_PARSE_H */
