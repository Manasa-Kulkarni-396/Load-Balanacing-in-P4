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

header gre_t {
    bit<16> flag_ver;
    bit<16> protocol;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       inner_ipv4;
    gre_t        gre;
    ipv4_t       ipv4;
}

/*************************************************************************

*********************** P A R S E R  ***********************************

*************************************************************************/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) 

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
            0x2f: parse_gre;
            default: accept;
        }
    }

    state parse_gre {
        packet.extract(hdr.gre);
        transition select(hdr.gre.protocol) {
            0x0800: parse_inner_ipv4;
            default: accept;
        }
    }

    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
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

    action forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl=hdr.ipv4.ttl-1;
    }

    action gre_encap(ip4Addr_t src, ip4Addr_t dst, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.gre.setValid();
        hdr.gre.flag_ver=0;
        hdr.gre.protocol=0x0800;
        hdr.inner_ipv4.setValid();
        hdr.inner_ipv4.version=hdr.ipv4.version;
        hdr.inner_ipv4.ihl=hdr.ipv4.ihl;
        hdr.inner_ipv4.diffserv=hdr.ipv4.diffserv;
        hdr.inner_ipv4.totalLen=hdr.ipv4.totalLen;
        hdr.ipv4.totalLen=hdr.ipv4.totalLen+24; // add one ipv4 header + gre header
        hdr.inner_ipv4.identification= hdr.ipv4.identification;
        hdr.inner_ipv4.flags=hdr.ipv4.flags;
        hdr.inner_ipv4.fragOffset=hdr.ipv4.fragOffset;
        hdr.inner_ipv4.ttl=hdr.ipv4.ttl;
        hdr.ipv4.ttl=255;
        hdr.inner_ipv4.protocol=hdr.ipv4.protocol;
        hdr.ipv4.protocol=0x2f;
        hdr.inner_ipv4.hdrChecksum=hdr.ipv4.hdrChecksum;
        hdr.inner_ipv4.srcAddr=hdr.ipv4.srcAddr;
        hdr.inner_ipv4.dstAddr=hdr.ipv4.dstAddr;
        hdr.ipv4.srcAddr=src;
        hdr.ipv4.dstAddr=dst;
    }

    action gre_decap(egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ipv4.version=hdr.inner_ipv4.version;
        hdr.ipv4.ihl=hdr.inner_ipv4.ihl;
        hdr.ipv4.diffserv=hdr.inner_ipv4.diffserv;
        hdr.ipv4.totalLen=hdr.ipv4.totalLen-24;
        hdr.ipv4.identification= hdr.inner_ipv4.identification;
        hdr.ipv4.flags=hdr.inner_ipv4.flags;
        hdr.ipv4.fragOffset=hdr.inner_ipv4.fragOffset;
        hdr.ipv4.ttl=hdr.inner_ipv4.ttl;
        hdr.ipv4.protocol=hdr.inner_ipv4.protocol;
        hdr.ipv4.hdrChecksum=hdr.inner_ipv4.hdrChecksum;
        hdr.ipv4.srcAddr=hdr.inner_ipv4.srcAddr;
        hdr.ipv4.dstAddr=hdr.inner_ipv4.dstAddr;
        hdr.inner_ipv4.setInvalid();
        hdr.gre.setInvalid(); 
    }

    table ip_forward {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            gre_encap;
            forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    table gre_receive {
        key = {
            hdr.ipv4.dstAddr: lpm;

        }
        actions = {
            gre_decap;
            NoAction();
        }
        size = 1024;
        default_action = NoAction();
    }
    apply {
        ip_forward.apply();
        if(hdr.gre.isValid()) {
           gre_receive.apply();
        }
    }
}

/*************************************************************************

****************  E G R E S S   P R O C E S S I N G   *******************

*************************************************************************/
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    action setDstMac(macAddr_t dst) {
        hdr.ethernet.dstAddr=dst;  
    }

    table dstforward {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            setDstMac;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    apply {
       dstforward.apply();
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
        packet.emit(hdr.gre);
        packet.emit(hdr.inner_ipv4);
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
