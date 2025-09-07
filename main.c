#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>


int main (int argc, char *argv[]) {
    
    // no arguments given
    if (argc != 2){
        fprintf(stderr, "missing argument\n");
        return 1;
    }

    // open pcap file
    FILE *f = fopen(argv[1], "rb");

    // skip global header
    if (fseek(f,  24, SEEK_SET) != 0) {
        fprintf(stderr, "failed to read global header\n");
        fclose(f);
        return 1;
    }

    // read each UDP packet
    while (1) {

        // skip record header
        unsigned char record_header[16];
        size_t n = fread(record_header, 1, 16, f);
        if (n == 0) 
            break; // EOF
        if (n != 16) {
            fprintf(stderr, "failed to read record header\n");
            break;
        }

        // skip ethernet & IP header
        if (fseek(f, 14 + 20, SEEK_CUR) != 0) {
            fprintf(stderr, "failed to skip ethernet & IP header\n");
            break;
        }

        // read UDP header
        unsigned char udp_header[8];
        if (fread(udp_header, 1, 8, f) != 8) {
            printf("failed to read UDP header\n");
            break;
        }

        uint16_t srcport = ntohs(*(uint16_t*)(udp_header));
        uint16_t dstport = ntohs(*(uint16_t*)(udp_header + 2));
        uint16_t length= ntohs(*(uint16_t*)(udp_header + 4));
        uint16_t checksum = ntohs(*(uint16_t*)(udp_header + 6));

        printf("srcport: %u\n", srcport);
        printf("dstport: %u\n", dstport);
        printf("length: %u\n", length);
        printf("checksum: 0x%x\n", checksum);

        // read UDP payload
        long unsigned int len_payload = length - 8;
        unsigned char payload[len_payload];
        if (fread(payload, 1, len_payload, f) != len_payload) {
            printf("failed to read UDP payload\n");
            break;
        }

        // print UDP payload
        for (long unsigned int i = 0; i < len_payload; i++) {
            unsigned char c = payload[i];
            if (c >= 32 && c <= 126) 
                putchar(c);
            
            else
                putchar('.');
            
        }
        
        putchar('\n');
        printf("==================================\n");

    }
    
    fclose(f);
    return 0;
}
