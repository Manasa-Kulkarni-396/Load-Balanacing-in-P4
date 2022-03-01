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
        checksum : 16;
        urgentPtr : 16;
    }
}

header_type udp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        length_ : 16;
       checksum : 16;
    }
}

header_type mymetadata_t {
    fields {
        ecmp_select : 14;
    }
}
 
metadata mymetadata_t mymetadata;

header ethernet_t ethernet;
parser start {
    set_metadata(meta.if_index, standard_metadata.ingress_port);
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType){
      ETHERTYPE_IPV4 : parse_ipv4;
      ETHERTYPE_ARP  : parse_arp;
      default : ingress;
    }
}

header ipv4_t ipv4;

parser parse_ipv4 {
    extract(ipv4);
    set_metadata(meta.ipv4_sa, ipv4.srcAddr);
    set_metadata(meta.ipv4_da, ipv4.dstAddr);
    set_metadata(meta.tcpLength, ipv4.totalLen - 20);
    return select(latest.protocol) {
        IP_PROTOCOLS_TCP : parse_tcp;
        IP_PROTOCOLS_UDP : parse_udp;
        default: ingress;
    }
}
 
header arp_t arp;
parser parse_arp{
    extract(arp);
    return ingress;
}

header tcp_t tcp;
parser parse_tcp {
    extract(tcp);
    set_metadata(meta.tcp_sp, tcp.srcPort);
    set_metadata(meta.tcp_dp, tcp.dstPort);
    return ingress;

}

 

header udp_t udp;
parser parse_udp {
    extract(udp);
    return ingress;
}

header_type meta_t {
    fields {
        do_forward : 1;
        ipv4_sa : 32;
        ipv4_da : 32;
        tcp_sp : 16;
        tcp_dp : 16;
        nhop_ipv4 : 32;
        if_ipv4_addr : 32;
        if_mac_addr : 48;
        is_ext_if : 1;
        tcpLength : 16;
        if_index : 8;
    }
}


metadata meta_t meta;
field_list ipv4_checksum_list{
    ipv4.version;
    ipv4.ihl;
    ipv4.diffserv;
    ipv4.totalLen;
    ipv4.identification;
    ipv4.flags;
    ipv4.fragOffset;
    ipv4.ttl;
    ipv4.protocol;
    ipv4.srcAddr;
    ipv4.dstAddr;  
}

field_list_calculation ipv4_checksum{
    input {
      ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum {
    verify ipv4_checksum;
    update ipv4_checksum;
}

field_list tcp_checksum_list {
        ipv4.srcAddr;
        ipv4.dstAddr;
        8'0;
        ipv4.protocol;
        meta.tcpLength;
        tcp.srcPort;
        tcp.dstPort;
        tcp.seqNo;
        tcp.ackNo;
        tcp.dataOffset;
        tcp.res;
        tcp.flags;
        tcp.window;
        tcp.urgentPtr;
        payload;
}

field_list_calculation tcp_checksum {
    input {
        tcp_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field tcp.checksum {
    verify tcp_checksum;
    update tcp_checksum;
}

field_list my_hash_fields {
    ipv4.srcAddr;
    ipv4.dstAddr;
    ipv4.protocol;
    tcp.srcPort;
    tcp.dstPort;
}

field_list_calculation my_map_hash {
    input {
        my_hash_fields;
    }
    algorithm : crc16;
    output_width : 14;
}

action _drop() {
    drop();
}

action nop() {}
action set_ecmp_nhop( nhop_mac, nhop_ipv4, port) {
    modify_field(standard_metadata.egress_spec, port);
    modify_field(ipv4.dstAddr, nhop_ipv4);
    modify_field(ethernet.dstAddr, nhop_mac);
    add_to_field(ipv4.ttl, -1);
}

action set_ecmp_select(ecmp_base, ecmp_count) {
    modify_field_with_hash_based_offset(mymetadata.ecmp_select, ecmp_base,
                                        my_map_hash, ecmp_count);
    add_to_field(mymetadata.ecmp_select, 1);
}

table ecmp_group {
    reads {
      ipv4.dstAddr: lpm;
    }
    actions {
        _drop;
        set_ecmp_select;
        nop;
    }
    size: 1024;
}

table ecmp_nhop {
    reads {
      mymetadata.ecmp_select: exact;
    }
    actions {
        _drop;
        set_ecmp_nhop;
        nop;
    }
    size: 2;
}

action set_nhop(dmac, port) {
    modify_field(standard_metadata.egress_spec, port);
    modify_field(ethernet.dstAddr, dmac);
    add_to_field(ipv4.ttl, -1);
}

table forward {
    reads {
      ipv4.dstAddr: lpm;
    }
    actions {
        _drop;
        set_nhop;
        nop;
    }
    size: 1024;
}

action rewrite_sip(sip) {
    modify_field(ipv4.srcAddr, sip);
}

table send_frame {
    reads {
        standard_metadata.egress_port: exact;
    }
    actions {
        _drop;
        rewrite_sip;
        nop;
    }
    size: 256;
}

control ingress {
    apply(forward);
    apply(ecmp_group);
    apply(ecmp_nhop);
}

control egress {
    apply(send_frame);
}
