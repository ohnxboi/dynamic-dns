#include "dns_parse.h"

const char *code_to_str(enum dns_record_type in) {
    switch(in) {
    case DNS_RECORD_A: return "A";
    case DNS_RECORD_NS: return "NS";
    case DNS_RECORD_CNAME: return "CNAME";
    case DNS_RECORD_SOA: return "SOA";
    case DNS_RECORD_PTR: return "PTR";
    case DNS_RECORD_MX: return "MX";
    case DNS_RECORD_TXT: return "TXT";
    case DNS_RECORD_AAAA: return "AAAA";
    case DNS_RECORD_SRV: return "SRV";
    case DNS_RECORD_RRSIG: return "RRSIG";
    case DNS_RECORD_ANY: return "ANY";
    default: return "UNKNOWN";
    }
}

// convert DNS-style string to c-string
char *dns_str_convert(void *in) {
    unsigned int length = 0;
    char *ptr = (char *)in;
    char *ret, *tmp;
    
    while (*ptr != 0) {
        length += *ptr + 1;
        ptr += *ptr + 1;
    }

    tmp = ret = calloc(length+1, sizeof(char));
    ptr = (unsigned char *)in;

    while (*ptr != 0) {
        memcpy(tmp, ptr+1, *ptr);
        tmp += *ptr;
        *(tmp++) = '.';
        ptr += *ptr + 1;
    }
    return ret;
}

// convert c-style string to dns-style string
void *str_dns_convert(unsigned char *in) {
    unsigned int length = strlen(in) + 1;
    unsigned char *ret, *tmp, *ptr, *dlo;

    tmp = ret = calloc(length, sizeof(char));
    ptr = (unsigned char *)in;

    while (*ptr != 0) {
        dlo = strchr(ptr, '.');

        if (dlo == NULL) {
            // does not end with a . (root)
            break;
        }

        *tmp = dlo-ptr;
        memcpy(++tmp, ptr, dlo-ptr);
        tmp += dlo-ptr;
        ptr += dlo-ptr+1;
    }

    return ret;
}
