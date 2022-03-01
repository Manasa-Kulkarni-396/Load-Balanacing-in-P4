#include <core.p4>
#include <v1model.p4>

/*************************************************************************

*********************** H E A D E R S  ***********************************

*************************************************************************/
struct meta_t {
    bit<1>  do_forward;
    bit<32> ipv4_sa;
    bit<32> ipv4_da;
    bit<16> tcp_sp;
    bit<16> tcp_dp;
    bit<32> nhop_ipv4;
    bit<32> if_ipv4_addr;
    bit<48> if_mac_addr;
    bit<1>  is_ext_if;
    bit<16> tcpLength;
    bit<8>  if_index;
}

struct mymetadata_t {
    bit<13> flowlet_map_index;
    bit<3>  flowlet_select;
    bit<2>  myselect;
}

header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> opcode;
    bit<48> hwSrcAddr;
    bit<32> protoSrcAddr;
    bit<48> hwDstAddr;
    bit<32> protoDstAddr;
}


header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

struct metadata {
    meta_t       meta;
    mymetadata_t mymetadata;
}

struct headers {
    arp_t      arp;
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
}

/*************************************************************************

*********************** P A R S E R  ***********************************

*************************************************************************/

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
     state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }
     state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            16w0x806: parse_arp;
            default: accept;
        }
    }
     state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.meta.ipv4_sa = hdr.ipv4.srcAddr;
        meta.meta.ipv4_da = hdr.ipv4.dstAddr;
        meta.meta.tcpLength = hdr.ipv4.totalLen - 16w20;
        transition select(hdr.ipv4.protocol) {
            8w6: parse_tcp;
            8w17: parse_udp;
            default: accept;
        }
    }
     state parse_tcp {
        packet.extract(hdr.tcp);
        meta.meta.tcp_sp = hdr.tcp.srcPort;
        meta.meta.tcp_dp = hdr.tcp.dstPort;
        transition accept;
    }
     state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
     state start {
        meta.meta.if_index = (bit<8>)standard_metadata.ingress_port;
        transition parse_ethernet;
    }
}

/*************************************************************************

****************  E G R E S S   P R O C E S S I N G   *******************

*************************************************************************/
control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
     action _drop() {
        mark_to_drop();
    }
     action rewrite_sip(bit<32> sip) {
        hdr.ipv4.srcAddr = sip;
    }
     action nop() {
    }
     table send_frame {
        actions = {
            _drop;
            rewrite_sip;
            nop;
        }
        key = {
            standard_metadata.egress_port: exact;
        }
        size = 256;
    }
    apply {
        send_frame.apply();
    }
}

register<bit<3>>(32w8192) flowlet_select;
register<bit<2>>(32w1) myselect;
 
/*************************************************************************

**************  I N G R E S S   P R O C E S S I N G   *******************

*************************************************************************/

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
     action _drop() {
        mark_to_drop();
    }
     action set_ecmp_select() {
        hash(meta.mymetadata.flowlet_map_index, HashAlgorithm.crc16, (bit<13>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort, hdr.tcp.dstPort }, (bit<26>)8192);
        flowlet_select.read(meta.mymetadata.flowlet_select, (bit<32>)meta.mymetadata.flowlet_map_index);
        myselect.read(meta.mymetadata.myselect, (bit<32>)0);
        meta.mymetadata.myselect = meta.mymetadata.myselect + 2w1;
        meta.mymetadata.flowlet_select = (bit<3>)meta.mymetadata.myselect;
        myselect.write((bit<32>)0, (bit<2>)meta.mymetadata.myselect);
        flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, (bit<3>)meta.mymetadata.flowlet_select);
    }
     action nop() {
    }
     action rewrite() {
        myselect.write((bit<32>)0, 0);      
    }
     action set_ecmp_nhop(bit<48> nhop_mac, bit<32> nhop_ipv4, bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ipv4.dstAddr = nhop_ipv4;
        hdr.ethernet.dstAddr = nhop_mac;
        hdr.ipv4.ttl = hdr.ipv4.ttl + 8w255;
    }
     action set_nhop(bit<48> dmac, bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.dstAddr = dmac;
        hdr.ipv4.ttl = hdr.ipv4.ttl + 8w255;
    }

     action read_flowlet_select() {
        hash(meta.mymetadata.flowlet_map_index, HashAlgorithm.crc16, (bit<13>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort, hdr.tcp.dstPort }, (bit<26>)8192);
        flowlet_select.read(meta.mymetadata.flowlet_select, (bit<32>)meta.mymetadata.flowlet_map_index);
    }
     table ecmp_group {
        actions = {
            _drop;
            set_ecmp_select;
            nop;
        }
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        size = 1024;
    }
     table ecmp_nhop {
        actions = {
            _drop;
            set_ecmp_nhop;
            nop;
        }
        key = {
            meta.mymetadata.flowlet_select: exact;
        }
        size = 1024;
    }
     table forward {
        actions = {
            _drop;
            set_nhop;
            nop;
            read_flowlet_select;
        }
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        size = 1024;
    }
    apply {
        forward.apply();
        if (hdr.tcp.flags & 8w2 != 8w0) {
            ecmp_group.apply();
            if (meta.mymetadata.flowlet_select == 3)
            rewrite();
        }
        ecmp_nhop.apply();
    }
}

/*************************************************************************

***********************  D E P A R S E R  *******************************

*************************************************************************/
control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************

************   C H E C K S U M    V E R I F I C A T I O N   *************

*************************************************************************/
control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
        verify_checksum_with_payload(true, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 8w0, hdr.ipv4.protocol, meta.meta.tcpLength, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.tcp.seqNo, hdr.tcp.ackNo, hdr.tcp.dataOffset, hdr.tcp.res, hdr.tcp.flags, hdr.tcp.window, hdr.tcp.urgentPtr }, hdr.tcp.checksum, HashAlgorithm.csum16);
    }

}

/*************************************************************************

*************   C H E C K S U M    C O M P U T A T I O N   **************

*************************************************************************/
control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
        update_checksum_with_payload(true, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 8w0, hdr.ipv4.protocol, meta.meta.tcpLength, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.tcp.seqNo, hdr.tcp.ackNo, hdr.tcp.dataOffset, hdr.tcp.res, hdr.tcp.flags, hdr.tcp.window, hdr.tcp.urgentPtr }, hdr.tcp.checksum, HashAlgorithm.csum16);
    }
}

/*************************************************************************

***********************  S W I T C H  *******************************

*************************************************************************/
V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
