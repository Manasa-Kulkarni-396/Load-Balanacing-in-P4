#include <core.p4>
#include <v1model.p4>
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
    bit<3>  ecmp_select;   
    bit<1>  server1;
    bit<1>  server2;
    bit<1>  server3;
    bit<1>  server4;   
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
    @name(".meta")
    meta_t       meta;
    @name(".mymetadata")
    mymetadata_t mymetadata;
}

struct headers {
    @name(".arp")
    arp_t      arp;
    @name(".ethernet")
    ethernet_t ethernet;
    @name(".ipv4")
    ipv4_t     ipv4;
    @name(".tcp")
    tcp_t      tcp;
    @name(".udp")
    udp_t      udp;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".parse_arp") state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    @name(".parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            16w0x806: parse_arp;
            default: accept;
        }
    }

    @name(".parse_ipv4") state parse_ipv4 {
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

    @name(".parse_tcp") state parse_tcp {
        packet.extract(hdr.tcp);
        meta.meta.tcp_sp = hdr.tcp.srcPort;
        meta.meta.tcp_dp = hdr.tcp.dstPort;
        transition accept;
    }

    @name(".parse_udp") state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
    
    @name(".start") state start {
        meta.mymetadata.server1=0;
            meta.mymetadata.server2=0;
        meta.meta.if_index = (bit<8>)standard_metadata.ingress_port;
        transition parse_ethernet;
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("._drop") action _drop() {
        mark_to_drop(standard_metadata);
    }

    @name(".rewrite_sip") action rewrite_sip(bit<32> sip) {
        hdr.ipv4.srcAddr = sip;
    }

    @name(".nop") action nop() {
    }

    @name(".send_frame") table send_frame {
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
control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("._drop") action _drop() {
        mark_to_drop(standard_metadata);     
    }
 
    action _fail1(bit<1> fail){
        meta.mymetadata.server1=fail;
    }

    action _fail2(bit<1> fail){
        meta.mymetadata.server2=fail;
    }

    action _fail3(bit<1> fail){
        meta.mymetadata.server3=fail;
    }

    action _fail4(bit<1> fail){
        meta.mymetadata.server4=fail;
    }

    @name(".set_ecmp_select") action set_ecmp_select(bit<8> ecmp_base, bit<8> ecmp_count) {
        hash(meta.mymetadata.ecmp_select, HashAlgorithm.crc16, (bit<13>)ecmp_base, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort, hdr.tcp.dstPort }, (bit<26>)ecmp_count);
        meta.mymetadata.ecmp_select = meta.mymetadata.ecmp_select + 1;
        hash(meta.mymetadata.flowlet_map_index, HashAlgorithm.crc16, (bit<13>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort, hdr.tcp.dstPort }, (bit<26>)8192);
        flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, meta.mymetadata.ecmp_select);
    }

    action read_flowlet_select() {
        hash(meta.mymetadata.flowlet_map_index, HashAlgorithm.crc16, (bit<13>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort, hdr.tcp.dstPort }, (bit<26>)8192);
        flowlet_select.read(meta.mymetadata.ecmp_select, (bit<32>)meta.mymetadata.flowlet_map_index);
    }

    @name(".nop") action nop() {
    }
    
    @name(".set_ecmp_nhop") action set_ecmp_nhop(bit<48> nhop_mac, bit<32> nhop_ipv4, bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ipv4.dstAddr = nhop_ipv4;
        hdr.ethernet.dstAddr = nhop_mac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 8w1;
    }

    @name(".set_nhop") action set_nhop(bit<48> dmac, bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.dstAddr = dmac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 8w1;
    }

    @name(".ecmp_group") table ecmp_group {
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

    @name(".ecmp_nhop") table ecmp_nhop {
        actions = {
            _drop;
            set_ecmp_nhop;
            nop;
        }

        key = {
            meta.mymetadata.ecmp_select: exact;
        }

        size = 1024;
    }

    @name(".forward") table forward {
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

    table set_status1 {
        actions = {
            _fail1;
        }

        key = {
            hdr.ipv4.dstAddr: lpm;
        }

        size = 1;
    }

    table set_status2 {
        actions = {
            _fail2;
        }

        key = {
            hdr.ipv4.dstAddr: lpm;
        }

        size = 1;
    }

    table set_status3 {
        actions = {
            _fail3;
        }

        key = {
            hdr.ipv4.dstAddr: lpm;
        }

        size = 1;
    }

    table set_status4 {
        actions = {
            _fail4;
        }

        key = {
            hdr.ipv4.dstAddr: lpm;
        }

        size = 1;
    }

    apply {
        forward.apply();
        if (hdr.tcp.flags & 8w2 != 8w0) {
            ecmp_group.apply();      
        }
        
        if( set_status1.apply().hit && hdr.tcp.flags & 8w2 != 8w0 ) {
          // server1 fails and the lb chooses server1
          if(meta.mymetadata.server1 == 1 && meta.mymetadata.ecmp_select==1){
            hash(meta.mymetadata.flowlet_map_index, HashAlgorithm.crc16, (bit<13>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort, hdr.tcp.dstPort }, (bit<26>)8192);
            //see server2 whether it fails or not. if not, choose server 2
       if(meta.mymetadata.server2 != 1){
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 2);
                meta.mymetadata.ecmp_select=2;
            //see server3 whether it fails or not. if not, choose server 3
            } else if(meta.mymetadata.server3 != 1){
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 3);
                meta.mymetadata.ecmp_select=3;
            //see server4 whether it fails or not. if not, choose server 4
            } else if(meta.mymetadata.server4 != 1){
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 4);
                meta.mymetadata.ecmp_select=4;
            //all servers fail
            }else {
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 0);  
                meta.mymetadata.ecmp_select=0;
                _drop();
            }
          }
        }

 

        if( set_status2.apply().hit && hdr.tcp.flags & 8w2 != 8w0 ) {
          // server2 fails and the lb chooses server2
          if(meta.mymetadata.server2 == 1 && meta.mymetadata.ecmp_select==2){
            hash(meta.mymetadata.flowlet_map_index, HashAlgorithm.crc16, (bit<13>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort, hdr.tcp.dstPort }, (bit<26>)8192);
 

            //see server3 whether it fails or not. if not, choose server 3        
            if(meta.mymetadata.server3 != 1){
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 3);
                meta.mymetadata.ecmp_select=3;
 
            //see server4 whether it fails or not. if not, choose server 4
            } else if(meta.mymetadata.server4 != 1){
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 4);
                meta.mymetadata.ecmp_select=4;
 
            //see server1 whether it fails or not. if not, choose server 1
            } else if(meta.mymetadata.server4 != 1){
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 1);
                meta.mymetadata.ecmp_select=1;
 
            //all servers fail
            } else {
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 0);  
                meta.mymetadata.ecmp_select=0;   
                _drop();
            }
          }  
        }

        if( set_status3.apply().hit && hdr.tcp.flags & 8w2 != 8w0 ) {
          // server3 fails and the lb chooses server3
          if(meta.mymetadata.server3 == 1 && meta.mymetadata.ecmp_select==3){
            hash(meta.mymetadata.flowlet_map_index, HashAlgorithm.crc16, (bit<13>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort, hdr.tcp.dstPort }, (bit<26>)8192);

            //see server4 whether it fails or not. if not, choose server 4        
            if(meta.mymetadata.server4 != 1){
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 4);
                meta.mymetadata.ecmp_select=4;
 
            //see server1 whether it fails or not. if not, choose server 1
            } else if(meta.mymetadata.server1 != 1){
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 1);
                meta.mymetadata.ecmp_select=1;

            //see server2 whether it fails or not. if not, choose server 2
            } else if(meta.mymetadata.server2 != 1){
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 2);
                meta.mymetadata.ecmp_select=2;

            //all servers fail
            } else {
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 0);  
                meta.mymetadata.ecmp_select=0;
                _drop();
            }
          }  
        }

        if( set_status4.apply().hit && hdr.tcp.flags & 8w2 != 8w0 ) {
          // server4 fails and the lb chooses server4

          if(meta.mymetadata.server4 == 1 && meta.mymetadata.ecmp_select==4){
            hash(meta.mymetadata.flowlet_map_index, HashAlgorithm.crc16, (bit<13>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort, hdr.tcp.dstPort }, (bit<26>)8192);

            //see server1 whether it fails or not. if not, choose server 1        
            if(meta.mymetadata.server1 != 1){
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 1);
                meta.mymetadata.ecmp_select=1;
 
            //see server2 whether it fails or not. if not, choose server 2
            } else if(meta.mymetadata.server2 != 1){
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 2);
                meta.mymetadata.ecmp_select=2;

 

            //see server3 whether it fails or not. if not, choose server 3
            } else if(meta.mymetadata.server4 != 1){
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 3);
                meta.mymetadata.ecmp_select=3;

 
            //all servers fail
            } else {
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 0);  
                meta.mymetadata.ecmp_select=0;
                _drop();
            }
          }  
        }


        if(hdr.ipv4.isValid()){
          ecmp_nhop.apply();
        }
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
    }
}
 
control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
        verify_checksum_with_payload(true, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 8w0, hdr.ipv4.protocol, meta.meta.tcpLength, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.tcp.seqNo, hdr.tcp.ackNo, hdr.tcp.dataOffset, hdr.tcp.res, hdr.tcp.flags, hdr.tcp.window, hdr.tcp.urgentPtr }, hdr.tcp.checksum, HashAlgorithm.csum16);
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
        update_checksum_with_payload(true, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 8w0, hdr.ipv4.protocol, meta.meta.tcpLength, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.tcp.seqNo, hdr.tcp.ackNo, hdr.tcp.dataOffset, hdr.tcp.res, hdr.tcp.flags, hdr.tcp.window, hdr.tcp.urgentPtr }, hdr.tcp.checksum, HashAlgorithm.csum16);
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
