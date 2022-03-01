#define ETHERTYPE_IPV4 0x0800

#define ETHERTYPE_ARP  0x0806

#define IPPROTO_ICMP   0x01

#define IP_PROTOCOLS_TCP 6

#define IP_PROTOCOLS_UDP 17

#define ARP_HTYPE_ETHERNET  0x0001

#define ARP_PTYPE_IPV4      0x0800

#define ARP_HLEN_ETHERNET   6

#define ARP_PLEN_IPV4     4

#define ARP_OPER_REQUEST    1

#define ARP_OPER_REPLY      2

#define ICMP_ECHO_REQUEST   8

#define ICMP_ECHO_REPLY     0

 

header_type ethernet_t {

    fields {

        dstAddr : 48;

        srcAddr : 48;

        etherType : 16;

    }

}

 

header_type ipv4_t {

    fields {

        version : 4;

        ihl : 4;

        diffserv : 8;

        totalLen : 16;

        identification : 16;

        flags : 3;

        fragOffset : 13;

        ttl : 8;

        protocol : 8;

        hdrChecksum : 16;

        srcAddr : 32;

        dstAddr: 32;

    }

}

 

header_type arp_t {

    fields {

        htype : 16;

        ptype : 16;

        hlen : 8;

        plen : 8;

        opcode : 16;

        hwSrcAddr : 48;

        protoSrcAddr : 32;

        hwDstAddr : 48;

        protoDstAddr : 32;

    }

}

 

header_type tcp_t {

    fields {

        srcPort : 16;

        dstPort : 16;

        seqNo : 32;

        ackNo : 32;

        dataOffset : 4;

        res : 4;

        flags : 8;

        window : 16;
