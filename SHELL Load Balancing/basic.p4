/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
const bit<16> TYPE_IPV4 = 0x800;
/*************************************************************************

*********************** H E A D E R S  ***********************************

*************************************************************************/
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
register<bit<128>>(8) buffer;
register<bit<1>>(1) is_buffer_empty;
register<bit<3>>(1) cnt;
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> udplength;
    bit<16> checksum;
}

header flag_t {
    bit<8> type;
    bit<40> padding;
}

header msg_t {
    bit<128> msg;
}

header agg_t {
    bit<128> msg;
}

struct metadata {
    bit<1>   saved;
    bit<1>   empty;
    bit<3>   cnt;
    bit<1>   myaction; //0:aggregate 1:disaggregate
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t       udp;
    flag_t       flag;
    msg_t      msg;
    agg_t[8]     agg; 
}

/*************************************************************************

*********************** P A R S E R  ***********************************

*************************************************************************/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            0x11: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition parse_flag;
    }

    state parse_flag {
        packet.extract(hdr.flag);
        transition select(hdr.flag.type) {
            0x1: parse_msg;
            0x2: parse_agg;
            default: accept;
        }
    }

    state parse_msg {
        meta.saved=0;
        packet.extract(hdr.msg);
        transition accept;
    }

    state parse_agg {
        packet.extract(hdr.agg[0]);
        packet.extract(hdr.agg[1]);
        packet.extract(hdr.agg[2]);
        packet.extract(hdr.agg[3]);
        packet.extract(hdr.agg[4]);
        packet.extract(hdr.agg[5]);
        packet.extract(hdr.agg[6]);
        packet.extract(hdr.agg[7]);             
        transition accept;
    }
}

/*************************************************************************

************   C H E C K S U M    V E R I F I C A T I O N   *************

*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {  
    apply {  }
}

/*************************************************************************

**************  I N G R E S S   P R O C E S S I N G   *******************

*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop();
    }

    action check_cnt() {
        cnt.read(meta.cnt,(bit<32>)0);
    }

    action check_buffer_empty() {
        is_buffer_empty.read(meta.empty,(bit<32>)0);
    }

    action set_buffer_not_empty() {
        is_buffer_empty.write((bit<32>)0, 1);
    }

    action set_buffer_empty() {
        is_buffer_empty.write((bit<32>)0, 0);
    }

    action to_buffer() {
        buffer.write((bit<32>)meta.cnt,(bit<128>)hdr.msg.msg);
        meta.saved=1;
    }     

    action add_counter() {
        meta.cnt = meta.cnt + 1;
        cnt.write((bit<32>)0,(bit<3>)meta.cnt);
    }

    action set_Npkt() {
        hdr.agg.push_front(1);
        hdr.agg[0].setValid();
        buffer.read(hdr.agg[0].msg, (bit<32>)7);
        hdr.agg.push_front(1);
        hdr.agg[0].setValid();
        buffer.read(hdr.agg[0].msg, (bit<32>)6);
        hdr.agg.push_front(1);
        hdr.agg[0].setValid();   
        buffer.read(hdr.agg[0].msg, (bit<32>)5);
        hdr.agg.push_front(1);
        hdr.agg[0].setValid();
        buffer.read(hdr.agg[0].msg, (bit<32>)4);
        hdr.agg.push_front(1);
        hdr.agg[0].setValid();
        buffer.read(hdr.agg[0].msg, (bit<32>)3);
        hdr.agg.push_front(1);
        hdr.agg[0].setValid();
        buffer.read(hdr.agg[0].msg, (bit<32>)2);
        hdr.agg.push_front(1);
        hdr.agg[0].setValid();
        buffer.read(hdr.agg[0].msg, (bit<32>)1);
        hdr.agg.push_front(1);
        hdr.agg[0].setValid();
        buffer.read(hdr.agg[0].msg, (bit<32>)0);
        hdr.udp.udplength =  (bit<16>) 142;
        hdr.ipv4.totalLen =  (bit<16>) 162;
    }
    action multicast_method() {
        standard_metadata.mcast_grp=1;
    }

    action forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }
    table phyforward {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }     

    action set_action(bit<1> myaction) {
        meta.myaction=myaction;
    }

    table setAction {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            set_action();
        }
        size = 1024;
    }               

    apply {
        setAction.apply();
        if(hdr.flag.type==1 && meta.myaction==0) {
           check_cnt();
           check_buffer_empty();
           if(meta.empty!=0 && meta.cnt==0) {
             set_Npkt();
             hdr.flag.type=2; //aggregated N-pkt
             set_buffer_empty();
             to_buffer();
             add_counter();
             hdr.msg.setInvalid();
           }


           if(meta.saved==0) {
             to_buffer();
             add_counter();
             set_buffer_not_empty();
             drop();
          }
        }

        if(hdr.flag.type==2 && meta.myaction==0) {
       phyforward.apply();
        }

        if(hdr.flag.type==2 && meta.myaction==1) {      
           multicast_method();
        }
    }
}

/*************************************************************************

****************  E G R E S S   P R O C E S S I N G   *******************

*************************************************************************/
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
      if(hdr.flag.type==2 && meta.myaction==1 && standard_metadata.egress_rid==0) {
         hdr.msg.setValid();
         hdr.msg.msg=hdr.agg[0].msg;
         hdr.agg[0].setInvalid();
         hdr.agg[1].setInvalid();
         hdr.agg[2].setInvalid();
         hdr.agg[3].setInvalid();
         hdr.agg[4].setInvalid();
         hdr.agg[5].setInvalid();
         hdr.agg[6].setInvalid();
         hdr.agg[7].setInvalid(); 
         hdr.flag.type=1;   
         hdr.ipv4.totalLen=50;
         hdr.udp.udplength=30;
      } 

      if(hdr.flag.type==2 && meta.myaction==1 && standard_metadata.egress_rid==1) {
         hdr.msg.setValid();
         hdr.msg.msg=hdr.agg[1].msg;
         hdr.agg[0].setInvalid();
         hdr.agg[1].setInvalid();
         hdr.agg[2].setInvalid();
         hdr.agg[3].setInvalid();
         hdr.agg[4].setInvalid();
         hdr.agg[5].setInvalid();
         hdr.agg[6].setInvalid();
         hdr.agg[7].setInvalid(); 
         hdr.flag.type=1;
         hdr.ipv4.totalLen=50;
         hdr.udp.udplength=30;
      }

 
      if(hdr.flag.type==2 && meta.myaction==1 && standard_metadata.egress_rid==2) {
         hdr.msg.setValid();
         hdr.msg.msg=hdr.agg[2].msg;
         hdr.agg[0].setInvalid();
         hdr.agg[1].setInvalid();
         hdr.agg[2].setInvalid();
         hdr.agg[3].setInvalid();
         hdr.agg[4].setInvalid();
         hdr.agg[5].setInvalid();
         hdr.agg[6].setInvalid();
         hdr.agg[7].setInvalid(); 
         hdr.flag.type=1;
         hdr.ipv4.totalLen=50;
         hdr.udp.udplength=30;
      } 


      if(hdr.flag.type==2 && meta.myaction==1 && standard_metadata.egress_rid==3) {
         hdr.msg.setValid();
         hdr.msg.msg=hdr.agg[3].msg;
         hdr.agg[0].setInvalid();
         hdr.agg[1].setInvalid();
         hdr.agg[2].setInvalid();
         hdr.agg[3].setInvalid();
         hdr.agg[4].setInvalid();
         hdr.agg[5].setInvalid();
         hdr.agg[6].setInvalid();
         hdr.agg[7].setInvalid(); 
         hdr.flag.type=1;
         hdr.ipv4.totalLen=50;
         hdr.udp.udplength=30;
      }  

      if(hdr.flag.type==2 && meta.myaction==1 && standard_metadata.egress_rid==4) {
         hdr.msg.setValid();
         hdr.msg.msg=hdr.agg[4].msg;
         hdr.agg[0].setInvalid();
         hdr.agg[1].setInvalid();
         hdr.agg[2].setInvalid();
         hdr.agg[3].setInvalid();
         hdr.agg[4].setInvalid();
         hdr.agg[5].setInvalid();
         hdr.agg[6].setInvalid();
         hdr.agg[7].setInvalid(); 
         hdr.flag.type=1;
         hdr.ipv4.totalLen=50;
         hdr.udp.udplength=30;
      }  

      if(hdr.flag.type==2 && meta.myaction==1 && standard_metadata.egress_rid==5) {
         hdr.msg.setValid();
         hdr.msg.msg=hdr.agg[5].msg;
         hdr.agg[0].setInvalid();
         hdr.agg[1].setInvalid();
         hdr.agg[2].setInvalid();
         hdr.agg[3].setInvalid();
         hdr.agg[4].setInvalid();
         hdr.agg[5].setInvalid();
         hdr.agg[6].setInvalid();
         hdr.agg[7].setInvalid(); 
         hdr.flag.type=1;
         hdr.ipv4.totalLen=50;
         hdr.udp.udplength=30;
      } 


      if(hdr.flag.type==2 && meta.myaction==1 && standard_metadata.egress_rid==6) {
         hdr.msg.setValid();
         hdr.msg.msg=hdr.agg[6].msg;
         hdr.agg[0].setInvalid();
         hdr.agg[1].setInvalid();
         hdr.agg[2].setInvalid();
         hdr.agg[3].setInvalid();
         hdr.agg[4].setInvalid();
         hdr.agg[5].setInvalid();
         hdr.agg[6].setInvalid();
         hdr.agg[7].setInvalid(); 
         hdr.flag.type=1;
         hdr.ipv4.totalLen=50;
         hdr.udp.udplength=30;
      }  

 
      if(hdr.flag.type==2 && meta.myaction==1 && standard_metadata.egress_rid==7) {
         hdr.msg.setValid();
         hdr.msg.msg=hdr.agg[7].msg;
         hdr.agg[0].setInvalid();
         hdr.agg[1].setInvalid();
         hdr.agg[2].setInvalid();
         hdr.agg[3].setInvalid();
         hdr.agg[4].setInvalid();
         hdr.agg[5].setInvalid();
         hdr.agg[6].setInvalid();
         hdr.agg[7].setInvalid(); 
         hdr.flag.type=1;
         hdr.ipv4.totalLen=50;
         hdr.udp.udplength=30;
      }  
    }
}


/*************************************************************************

*************   C H E C K S U M    C O M P U T A T I O N   **************

*************************************************************************/
control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************

***********************  D E P A R S E R  *******************************

*************************************************************************/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.flag);
        packet.emit(hdr.msg);
        packet.emit(hdr.agg);     
    }
}


/*************************************************************************

***********************  S W I T C H  *******************************

*************************************************************************/
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
