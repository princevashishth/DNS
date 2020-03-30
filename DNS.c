
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#define ISVALIDSOCKET(s) ((s) >= 0)
#define CLOSESOCKET(s) close(s)
#define SOCKET int
#define GETSOCKETERRNO() (errno)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//below is name printing function   //  all are pointers
const unsigned char *print_name(const unsigned char *msg,                         
        const unsigned char *p, const unsigned char *end) {

    if (p + 2 > end) {
        fprintf(stderr, "End of message.\n"); exit(1);} //checking if a proper name is possible
//p is pointer to the name to print


    if ((*p & 0xC0) == 0xC0) {    
        const int k = ((*p & 0x3F) << 8) + p[1];    //we take the lower 6 bits of *p and all 8 bits of p[1]
        p += 2;
        print_name(msg, msg+k, end); 
        return p;

    } else {  //If the name is not a pointer, we simply print it one label at a time
        const int len = *p++;
        if (p + len + 1 > end) {
            fprintf(stderr, "End of message.\n"); exit(1);}

        printf("%.*s", len, p);           // printf("%.*s\n", str_len, str)
        p += len;
        if (*p) {
            printf(".");
            return print_name(msg, p, end); //recursive calls to print the next label of the name
        } else {
            return p+1;    //returns end of question or beginning of qtype
        }
    }
}
//  DNS messages share the same fromat for request and response 
void print_dns_message(const char *message, int msg_length) { // we have beginning of message and total message length

    if (msg_length < 12) {        //Only DNS header is 12 bytes long
        fprintf(stderr, "ERROR:DNS Header must be of minimum 12 bytes\n");
        exit(1);
    }

    const unsigned char *msg = (const unsigned char *)message; 

    printf("ID = %0X %0X\n", msg[0], msg[1]);  // message id is first two bytes

    const int qr = (msg[2] & 0x80) >> 7; // using 0x80 as bitmask to see if message is response otherwise it's a query  0 means response
    printf("QR = %d %s\n", qr, qr ? "response" : "query");

    const int opcode = (msg[2] & 0x78) >> 3;
    printf("OPCODE = %d ", opcode);
    switch(opcode) {
        case 0: printf("standard\n"); break;
        case 1: printf("reverse\n"); break;
        case 2: printf("status\n"); break;
        default: printf("?\n"); break;
    }

    const int aa = (msg[2] & 0x04) >> 2;
    printf("AA = %d %s\n", aa, aa ? "authoritative" : "");

    const int tc = (msg[2] & 0x02) >> 1;
    printf("TC = %d %s\n", tc, tc ? "message truncated" : "");

    const int rd = (msg[2] & 0x01);
    printf("RD = %d %s\n", rd, rd ? "recursion desired" : "");

    if (qr) {  //here we read rcode for response type messages  
        const int rcode = msg[3] & 0x07;
        printf("RCODE = %d ", rcode);
        switch(rcode) {
            case 0: printf("success\n"); break;
            case 1: printf("format error\n"); break;
            case 2: printf("server failure\n"); break;
            case 3: printf("name error\n"); break;
            case 4: printf("not implemented\n"); break;
            case 5: printf("refused\n"); break;
            default: printf("?\n"); break;
        }
        if (rcode != 0) return;
    }
 
// here we print last 4 fields
    const int qdcount = (msg[4] << 8) + msg[5];
    const int ancount = (msg[6] << 8) + msg[7];
    const int nscount = (msg[8] << 8) + msg[9];
    const int arcount = (msg[10] << 8) + msg[11];

    printf("QDCOUNT = %d\n", qdcount);
    printf("ANCOUNT = %d\n", ancount);
    printf("NSCOUNT = %d\n", nscount);
    printf("ARCOUNT = %d\n", arcount);

// uptil now we have read the DNS Message header(the first 12 bytes)
// now we will read rest of the message

    const unsigned char *p = msg + 12;
    const unsigned char *end = msg + msg_length;
//We set the end variable to one past the end of the message

//We read and print each question in the DNS message with the following code:
    if (qdcount) {                          //qdcount for question    always there is 1 question
        int i;
        for (i = 0; i < qdcount; ++i) { // we loop through each question       there is one question most of the time
            if (p >= end) {
                fprintf(stderr, "Message ended early\n"); exit(1);}

            printf("Query %2d\n", i + 1);
            printf("  name: ");

            p = print_name(msg, p, end); printf("\n"); // print the question name 

            if (p + 4 > end) {
                fprintf(stderr, "End of message.\n"); exit(1);}

            const int type = (p[0] << 8) + p[1];
            printf("  type: %d\n", type);   //print question type
            p += 2;

            const int qclass = (p[0] << 8) + p[1];
            printf(" class: %d\n", qclass);   //print question class
            p += 2;
        }
    }

//below code will only execute if it is a answer, above code will only execute if it is a question

    if (ancount || nscount || arcount) {             // all three are zero in beginning
        int i;
        for (i = 0; i < ancount + nscount + arcount; ++i) {
            if (p >= end) {
                fprintf(stderr, "Message ended early\n"); exit(1);}

            printf("Answer %2d\n", i + 1);
            printf("  name: ");

            p = print_name(msg, p, end); printf("\n");

            if (p + 10 > end) {
                fprintf(stderr, "Answer format short\n"); exit(1);}

            const int type = (p[0] << 8) + p[1];
            printf("  type: %d\n", type);
            p += 2;

            const int qclass = (p[0] << 8) + p[1];
            printf(" class: %d\n", qclass); //we stored the class in a variable called qclass
            p += 2;

//Reading ttl and data length below
            const unsigned int ttl = (p[0] << 24) + (p[1] << 16) +
                (p[2] << 8) + p[3];
            printf("   ttl: %u\n", ttl);
            p += 4;

            const int rdlen = (p[0] << 8) + p[1];
            printf(" rdlen: %d\n", rdlen);
            p += 2;

            if (p + rdlen > end) {
                fprintf(stderr, "End of message.\n"); exit(1);} // so that we do not read past the end of the message
//we limit this to the A , MX , AAAA ,TXT , and CNAME records

            if (rdlen == 4 && type == 1) {
                // A Record 
                printf("IPv4 Address: %d.%d.%d.%d\n", p[0], p[1], p[2], p[3]);
                

            } else if (rdlen == 16 && type == 28) {
                // AAAA Record 
                printf("IPv6 Address ");
                int j;
                for (j = 0; j < rdlen; j+=2) {
                    printf("%02x%02x", p[j], p[j+1]);
                    if (j + 2 < rdlen) printf(":");
                }
                printf("\n");

            } else if (type == 15 && rdlen > 3) {
                // MX Record 
                const int preference = (p[0] << 8) + p[1];
                printf("  pref: %d\n", preference);
                printf("MX Record: ");
                print_name(msg, p+2, end); printf("\n");

            } else if (type == 16) {
                // TXT Record 
                printf("TXT Record: '%.*s'\n", rdlen-1, p+1);

            } else if (type == 5) {
                // CNAME Record 
                printf("CNAME: ");
                print_name(msg, p, end); printf("\n");
            }

            p += rdlen;
//finishing the loop here
        }
    }

    if (p != end) {                  // p will point to end here
        printf("There is some unread data left over.\n"); // we do not care about left over data
    }

    printf("\n");
}


int main(int argc, char *argv[]) {

    if (argc < 3) {
        printf("Usage:\n\t./DNS hostname type\n");
        printf("Example:\n\t./DNS Amazon.com a\n");
        exit(0);
    }

    if (strlen(argv[1]) > 255) {
        fprintf(stderr, "Hostname too long.");
        exit(1);
    }

    unsigned char type;
    if (strcmp(argv[2], "a") == 0) {
        type = 1;
    } else if (strcmp(argv[2], "mx") == 0) {
        type = 15;
    } else if (strcmp(argv[2], "txt") == 0) {
        type = 16;
    } else if (strcmp(argv[2], "aaaa") == 0) {
        type = 28;
    } else if (strcmp(argv[2], "any") == 0) {
        type = 255;
    } else {
        fprintf(stderr, "Unknown type '%s'. Use a, aaaa, txt, mx, or any.",
                argv[2]);
        exit(1);
    }


    printf("Configuring remote address...\n");
    
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));  // 8.8.8.8 is public dns server run by google and for port we connect to 53
    hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo *peer_address;
    if (getaddrinfo("8.8.8.8", "53", &hints, &peer_address)) {
        fprintf(stderr, "getaddrinfo() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }

//creating socket below
    printf("Creating socket...\n");
    SOCKET socket_peer;
    socket_peer = socket(peer_address->ai_family,
            peer_address->ai_socktype, peer_address->ai_protocol);
    if (!ISVALIDSOCKET(socket_peer)) {
        fprintf(stderr, "socket() failed. (%d)\n", GETSOCKETERRNO());
        return 1;
    }

//first 12 bytes compose the header of DNS message 
    char query[1024] = {0xCD, 0xEF, // ID 
                        0x01, 0x00, // Set recursion  attaching 1 question as only 1 question is supported by any dns server
                        0x00, 0x01, // QDCOUNT 
                        0x00, 0x00, // ANCOUNT 
                        0x00, 0x00, // NSCOUNT 
                        0x00, 0x00  }; // ARCOUNT

    char *p = query + 12; // pointer p set to end of query header
    char *h = argv[1];  // pointer h to loop through the hostname
//encode the user's desired hostname into the query
    while(*h) {         //while(*h == 0)
        char *len = p;
        p++;
        if (h != argv[1]) ++h;  //  what we are basically doing is making hostname in desired format

        while(*h && *h != '.') *p++ = *h++; // copy elements until we find a dot or the end of the hostname
        *len = p - len - 1; //If either is found, the code sets *len equal to the label length
    }

    *p++ = 0;
    *p++ = 0x00; *p++ = type; /* QTYPE */  //add the question type and question class to the query
    *p++ = 0x00; *p++ = 0x01; /* QCLASS */


    const int query_size = p - query; //finding query size    //query_size is total query size including header and all
    printf("Connecting to Google DNS server...\n");                                       
    int bytes_sent = sendto(socket_peer,
            query, query_size,
            0,
            peer_address->ai_addr, peer_address->ai_addrlen);

    printf("Sent %d bytes.\n", bytes_sent);

    print_dns_message(query, query_size);  // display the query we sent, here we use for debugging

    char read[1024];    // Read buffer
    int bytes_received = recvfrom(socket_peer,
            read, 1024, 0, 0, 0); // we can also try to see if some other message is received instead of that

    printf("Received %d bytes.\n", bytes_received);

    print_dns_message(read, bytes_received);
    printf("\n");


    freeaddrinfo(peer_address);
    CLOSESOCKET(socket_peer);


    return 0;
}
