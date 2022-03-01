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
    bit<8>  flowlet_select;
    bit<8>  myselect;
    bit<8>  choice;
    bit<1>  server1;
    bit<1>  server2;
    bit<1>  server3;
    bit<1>  server4;
    bit<8>  weight1;
    bit<8>  weight2;              
    bit<8>  weight3;
    bit<8>  weight4;              
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
        meta.meta.if_index = (bit<8>)standard_metadata.ingress_port;
        meta.mymetadata.myselect=0;
        meta.mymetadata.server1=0;
        meta.mymetadata.server2=0;
        meta.mymetadata.server3=0;
        meta.mymetadata.server4=0; 
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

@name(".flowlet_select") register<bit<8>>(32w8192) flowlet_select;
 
@name(".myselect") register<bit<8>>(32w1) myselect;

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name("._drop") action _drop() {
        mark_to_drop(standard_metadata);
    }

    @name(".set_ecmp_select") action set_ecmp_select() {
        myselect.read(meta.mymetadata.myselect, (bit<32>)0);
        meta.mymetadata.myselect = meta.mymetadata.myselect + 1;
        myselect.write((bit<32>)0, (bit<8>)meta.mymetadata.myselect);
    }

    @name(".nop") action nop() {
    }

    @name(".set_ecmp_nhop") action set_ecmp_nhop(bit<48> nhop_mac, bit<32> nhop_ipv4, bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ipv4.dstAddr = nhop_ipv4;
        hdr.ethernet.dstAddr = nhop_mac;
        hdr.ipv4.ttl = hdr.ipv4.ttl + 8w255;
    }

    @name(".set_nhop") action set_nhop(bit<48> dmac, bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.dstAddr = dmac;
        hdr.ipv4.ttl = hdr.ipv4.ttl + 8w255;
    }

    @name(".read_flowlet_select") action read_flowlet_select() {
        hash(meta.mymetadata.flowlet_map_index, HashAlgorithm.crc16, (bit<13>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort, hdr.tcp.dstPort }, (bit<26>)8192);
        flowlet_select.read(meta.mymetadata.flowlet_select, (bit<32>)meta.mymetadata.flowlet_map_index);
        meta.mymetadata.choice=meta.mymetadata.flowlet_select;
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

    action weight(bit<8> w1, bit<8> w2, bit<8> w3, bit<8> w4){
        meta.mymetadata.weight1=w1;
        meta.mymetadata.weight2=w2;
        meta.mymetadata.weight3=w3;
        meta.mymetadata.weight4=w4;
    }

    table set_weight {
        actions = {
            weight;
            nop;
        }
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        size = 1024;
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
            meta.mymetadata.choice: exact;
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
        if (hdr.tcp.flags & 8w2 != 8w0 && hdr.ipv4.dstAddr==0x0a000001) {
            set_weight.apply();
            ecmp_group.apply();
            if(meta.mymetadata.myselect<=meta.mymetadata.weight1){
                meta.mymetadata.choice=1;
            } else if ((meta.mymetadata.myselect > meta.mymetadata.weight1) && (meta.mymetadata.myselect <= (meta.mymetadata.weight1+meta.mymetadata.weight2))){
                meta.mymetadata.choice=2;
            } else if ((meta.mymetadata.myselect > (meta.mymetadata.weight1+meta.mymetadata.weight2)) && (meta.mymetadata.myselect <= (meta.mymetadata.weight1+meta.mymetadata.weight2+meta.mymetadata.weight3))){
                meta.mymetadata.choice=3;
            } else if ((meta.mymetadata.myselect > (meta.mymetadata.weight1+meta.mymetadata.weight2+meta.mymetadata.weight3)) && (meta.mymetadata.myselect <= (meta.mymetadata.weight1+meta.mymetadata.weight2+meta.mymetadata.weight3+meta.mymetadata.weight4))){
                meta.mymetadata.choice=4;
            }
            hash(meta.mymetadata.flowlet_map_index, HashAlgorithm.crc16, (bit<13>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort, hdr.tcp.dstPort }, (bit<26>)8192);
            flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, (bit<8>)meta.mymetadata.choice);

           if (meta.mymetadata.myselect == (meta.mymetadata.weight1+meta.mymetadata.weight2+meta.mymetadata.weight3+meta.mymetadata.weight4)) {
               meta.mymetadata.myselect=0;
               myselect.write((bit<32>)0, (bit<8>)meta.mymetadata.myselect);  
            }
        }


        if( set_status1.apply().hit && hdr.tcp.flags & 8w2 != 8w0 ) {
          // server1 fails and the lb chooses server1
          if(meta.mymetadata.server1 == 1 && meta.mymetadata.choice==1){
            hash(meta.mymetadata.flowlet_map_index, HashAlgorithm.crc16, (bit<13>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort, hdr.tcp.dstPort }, (bit<26>)8192);
            //see server2 whether it fails or not. if not, choose server 2
            if(meta.mymetadata.server2 != 1){
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 2);
                myselect.write((bit<32>)0, (bit<8>)(meta.mymetadata.weight1+1));
                meta.mymetadata.choice=2;
            //see server3 whether it fails or not. if not, choose server 3
            } else if(meta.mymetadata.server3 != 1){
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 3);
                myselect.write((bit<32>)0, (bit<8>)(meta.mymetadata.weight1+meta.mymetadata.weight2+1));       
                meta.mymetadata.choice=3;
            //see server4 whether it fails or not. if not, choose server 4
            } else if(meta.mymetadata.server4 != 1){
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 4);
                myselect.write((bit<32>)0, (bit<8>)(meta.mymetadata.weight1+meta.mymetadata.weight2+meta.mymetadata.weight3+1));     
                meta.mymetadata.choice=4;
           
           //all servers fail
            }else {
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 0);  
                meta.mymetadata.choice=0;
                _drop();
            }
          }
        }

        if( set_status2.apply().hit && hdr.tcp.flags & 8w2 != 8w0 ) {
          // server2 fails and the lb chooses server2
          if(meta.mymetadata.server2 == 1 && meta.mymetadata.choice==2){
            hash(meta.mymetadata.flowlet_map_index, HashAlgorithm.crc16, (bit<13>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort, hdr.tcp.dstPort }, (bit<26>)8192);
 
            //see server3 whether it fails or not. if not, choose server 3          
            if(meta.mymetadata.server3 != 1){
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 3);
                myselect.write((bit<32>)0, (bit<8>)(meta.mymetadata.weight1+meta.mymetadata.weight2+1));       
                meta.mymetadata.choice=3;

            //see server4 whether it fails or not. if not, choose server 4

            } else if(meta.mymetadata.server4 != 1){
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 4);
                myselect.write((bit<32>)0, (bit<8>)(meta.mymetadata.weight1+meta.mymetadata.weight2+meta.mymetadata.weight3+1));     
                meta.mymetadata.choice=4;

            //see server1 whether it fails or not. if not, choose server 1
            } else if(meta.mymetadata.server4 != 1){
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 1);
                myselect.write((bit<32>)0, (bit<8>)1);       
                meta.mymetadata.choice=1;

            //all servers fail
            } else {
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 0);  
                meta.mymetadata.choice=0;
                _drop();
            }
          } 
        }

        if( set_status3.apply().hit && hdr.tcp.flags & 8w2 != 8w0 ) {
          // server3 fails and the lb chooses server3
          if(meta.mymetadata.server3 == 1 && meta.mymetadata.choice==3){
            hash(meta.mymetadata.flowlet_map_index, HashAlgorithm.crc16, (bit<13>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort, hdr.tcp.dstPort }, (bit<26>)8192);
 
            //see server4 whether it fails or not. if not, choose server 4          
            if(meta.mymetadata.server4 != 1){
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 4);
                myselect.write((bit<32>)0, (bit<8>)(meta.mymetadata.weight1+meta.mymetadata.weight2+meta.mymetadata.weight3+1));     
                meta.mymetadata.choice=4;

            //see server1 whether it fails or not. if not, choose server 1
            } else if(meta.mymetadata.server1 != 1){
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 1);
                myselect.write((bit<32>)0, (bit<8>)1);       
                meta.mymetadata.choice=1;

            //see server2 whether it fails or not. if not, choose server 2
            } else if(meta.mymetadata.server2 != 1){
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 2);
                myselect.write((bit<32>)0, (bit<8>)(meta.mymetadata.weight1+1));
                meta.mymetadata.choice=2;

            //all servers fail
            } else {
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 0);  
                meta.mymetadata.choice=0;
                _drop();
            }
          } 
        }

        if( set_status4.apply().hit && hdr.tcp.flags & 8w2 != 8w0 ) {
          // server4 fails and the lb chooses server4
          if(meta.mymetadata.server4 == 1 && meta.mymetadata.choice==4){
            hash(meta.mymetadata.flowlet_map_index, HashAlgorithm.crc16, (bit<13>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort, hdr.tcp.dstPort }, (bit<26>)8192);

            //see server1 whether it fails or not. if not, choose server 1          
            if(meta.mymetadata.server1 != 1){
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 1);
                myselect.write((bit<32>)0, (bit<8>)1);       
                meta.mymetadata.choice=1;

            //see server2 whether it fails or not. if not, choose server 2
            } else if(meta.mymetadata.server2 != 1){
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 2);
                myselect.write((bit<32>)0, (bit<8>)(meta.mymetadata.weight1+1));
                meta.mymetadata.choice=2;

            //see server3 whether it fails or not. if not, choose server 3
            } else if(meta.mymetadata.server4 != 1){
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 3);
                myselect.write((bit<32>)0, (bit<8>)(meta.mymetadata.weight1+meta.mymetadata.weight2+1));       
                meta.mymetadata.choice=3;

            //all servers fail
            } else {
                flowlet_select.write((bit<32>)meta.mymetadata.flowlet_map_index, 0);  
                meta.mymetadata.choice=0;
                _drop();
            }
          } 
        }

        if(hdr.ipv4.isValid() && hdr.ipv4.dstAddr==0x0a000001){
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
