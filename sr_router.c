/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/


void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */


/*---------------------------------------------------------------------
 * Method: send_to_next_hop(..) 
 * Scope:  Global
 *
 * Looks up the cache to find the MAC address of the next plausible point
 * of the root to destination indicated by its ip. If the MAC address of the
 * next plausible point is available, send to that MAC address. If not,
 * queue the packet with request associated with it.  
 *
 ---------------------------------------------------------------------*/
void send_to_next_hop(
        struct sr_instance *sr,
        uint8_t *packet,
        unsigned int len, 
        uint32_t destination_ip, 
        struct sr_if* if_entry) 
{
    struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, destination_ip);

    /* The MAC address for the next hop is available in the cache  */
    if (entry) {
        sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*) packet;
        memcpy(eth_hdr->ether_shost, if_entry->addr, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
        sr_send_packet(sr, packet, len, if_entry->name);
    }
    /* The MAC address not available in the cache */
    else{
        /* Queue the ARP request for the address */
        struct sr_arpreq* arpreq = sr_arpcache_queuereq(&sr->cache, 
                                                        destination_ip, 
                                                        packet, 
                                                        len, 
                                                        if_entry->name);
        handle_arpreq(sr, arpreq);
    }
}


/*---------------------------------------------------------------------
 * Method: send_outstanding_packet(..) 
 * Scope: Local 
 *
 * Method used when ARP reply is received associated with a request. All 
 * packets waiting for the ARP reply associated with the request is sent
 * through this method.
 *
 ---------------------------------------------------------------------*/
void send_outstanding_packet(
        struct sr_instance* sr, 
        sr_arp_hdr_t *arp_hdr, 
        struct sr_packet *req_packet) 
{
    sr_ethernet_hdr_t *buf_eth_hdr = (sr_ethernet_hdr_t *) req_packet->buf;

    /* Get the interface indicated by the queued request */
    struct sr_if *out_if = sr_get_interface(sr, req_packet->iface);

    /* Sets host address and destination address of the ARP packet */
    memcpy(buf_eth_hdr->ether_shost, out_if->addr, ETHER_ADDR_LEN);
    memcpy(buf_eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);

    /* Send the packet after setting it up */
    sr_send_packet(sr, req_packet->buf, req_packet->len, req_packet->iface);
}


/*---------------------------------------------------------------------
 * Method: ttlcheck_and_checksum(..) 
 * Scope: Local 
 *
 * Checks the Time To Live (TTL) value of the IP packet received. If the 
 * TTL is not valid, return 1. If TTL si valid, decrement its TTL by 1 a
 * nd recompute its checksum. 
 *
 ---------------------------------------------------------------------*/
int ttlcheck_and_checksum(sr_ip_hdr_t *ip_hdr) 
{
    if (ip_hdr->ip_ttl <= 1) {
        /* TTL not valid */
        return 1;
    } else {
        /* Reduce TTL */
        ip_hdr->ip_ttl -=1;

        /* Recompute check sum */
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
        return 0;
    }
}

/*---------------------------------------------------------------------
 * Method: arp_sanity_check(..) 
 * Scope: Local 
 *
 * Sanity check for ARP packet. If fail, return 1 otherwise 0
 *
 ---------------------------------------------------------------------*/
int arp_sanity_check(sr_arp_hdr_t * arp_hdr, unsigned int len) 
{
    /* Check the minimum length */
    if (len < sizeof(sr_arp_hdr_t)) {
        fprintf(stderr, "ARP packet shorter than minimum length. ");
        return 1;
    }

    /* Check for the hardware type */
    if (ntohs(arp_hdr->ar_hrd) != arp_hrd_ethernet) {
        fprintf(stderr, "Invalid hardware type. %x\n", ntohs(arp_hdr->ar_hrd));
        return 1;
    }

    /* Check for protocol type */
    if (ntohs(arp_hdr->ar_pro) != 0x800) {
        fprintf(stderr, "Invalid protocol type. %x\n", ntohs(arp_hdr->ar_pro));
        return 1;
    }

    /* Check for address length */
    if (arp_hdr->ar_hln != ETHER_ADDR_LEN) {
        fprintf(stderr, "Invalid address length. %d\n", arp_hdr->ar_hln);
        return 1;
    }
    
    /* Check for address protocol length */
    if (arp_hdr->ar_pln != 4) {
        fprintf(stderr, "Invalid length of protocol address. %d\n", arp_hdr->ar_pln);
        return 1;
    }
    
    return 0;
}

/*---------------------------------------------------------------------
 * Method: ip_sanity_check(..) 
 * Scope: Local 
 *
 * Sanity check for IP packet. If fail, return 1 otherwise 0
 *
 ---------------------------------------------------------------------*/
int ip_sanity_check(sr_ip_hdr_t *ip_hdr, unsigned int len) {
    /* Check for minimum length */
    if (len < sizeof(sr_ip_hdr_t)) {
        fprintf(stderr, "IP packet shorter than minimum length.\n");
        return 1;
    }

    /* Check out the length indicated on the header  */
    if (len < ntohs(ip_hdr->ip_len)) {
        fprintf(stderr, "The length indicated on the header is \
                shorter than the minimum length. %d\n", ntohs(ip_hdr->ip_len));
        return 1;
    }

    /* Check for the checksum */
    uint16_t indicated_sum = ip_hdr->ip_sum; 
    ip_hdr->ip_sum = 0;
    uint16_t checksum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
    if (checksum != indicated_sum) {
        fprintf(stderr, "Checksum does not match. Received: %x, Indicated: %x.\n", 
                checksum, indicated_sum);
        return 1;
    }
    ip_hdr->ip_sum = indicated_sum;
    
    return 0;
}


/*---------------------------------------------------------------------
 * Method: ip_sanity_check(..) 
 * Scope: Local 
 *
 * Sanity check for ICMP packet. If fail, return 1 otherwise 0 
 *
 ---------------------------------------------------------------------*/
int icmp_sanity_check(sr_icmp_hdr_t *icmp_hdr, unsigned int len) {
    /* Check for minimum length  */
    if (len < sizeof(sr_icmp_hdr_t)) {
        fprintf(stderr, "ICMP packet shorter than the minimum length\n");
        return 1;
    }

    /* Check for the checksum */
    uint16_t indicated_sum = icmp_hdr->icmp_sum;
    icmp_hdr->icmp_sum = 0;
    uint16_t checksum = cksum(icmp_hdr, len);
    if (checksum != indicated_sum) {
        fprintf(stderr, "ICMP packet fails checksum test.\
                Received: %x, Indicated: %x.\n", checksum, indicated_sum);
        return 1;
    }
    icmp_hdr->icmp_sum = indicated_sum;
    
    return 0;
}


/*---------------------------------------------------------------------
 * Method: create_arp_reply(..) 
 * Scope: Local 
 *
 * This method creates ARP reply packet by setting its attribute of 
 * ARP header to it appropriate values.
 *
 ---------------------------------------------------------------------*/
void create_arp_reply(
        uint8_t *new_packet, 
        sr_arp_hdr_t* arp_hdr, 
        struct sr_if *out_if) 
{
    /* Initialize the variables needed. */
    sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *) new_packet;
    sr_arp_hdr_t *new_arp_hdr = (sr_arp_hdr_t *) (new_packet + sizeof(sr_ethernet_hdr_t));

    /* Set up ethernet header  */
    memcpy(new_eth_hdr->ether_shost, out_if->addr, ETHER_ADDR_LEN);
    memcpy(new_eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    new_eth_hdr->ether_type = htons(ethertype_arp);

    /* Set up ARP header */
    new_arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    new_arp_hdr->ar_pro = htons(protocol_ipv4);
    new_arp_hdr->ar_hln = ETHER_ADDR_LEN;
    new_arp_hdr->ar_pln = 4;
    new_arp_hdr->ar_op =  htons(arp_op_reply);
    memcpy(new_arp_hdr->ar_sha, out_if->addr, ETHER_ADDR_LEN);
    new_arp_hdr->ar_sip =  out_if->ip; 
    memcpy(new_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    new_arp_hdr->ar_tip = arp_hdr->ar_sip;
}


/*---------------------------------------------------------------------
 * Method: icmp_t3_set_common(..) 
 * Scope: Global 
 *
 * Sets attributes of the ICMP headers common to all different types. 
 *
 ---------------------------------------------------------------------*/
void icmp_t3_set_common(
        sr_icmp_t3_hdr_t *icmp_t3_hdr,
        sr_ip_hdr_t *original_ip_hdr,
        unsigned int len, 
        int type, 
        int code) 
{
    icmp_t3_hdr->icmp_type = type;
    icmp_t3_hdr->icmp_code = code;
    icmp_t3_hdr->unused = 0;
    icmp_t3_hdr->next_mtu = 0;
    memcpy(icmp_t3_hdr->data, original_ip_hdr, ICMP_DATA_SIZE);
    icmp_t3_hdr->icmp_sum = 0;
    icmp_t3_hdr->icmp_sum = cksum(icmp_t3_hdr, len);
}


/*---------------------------------------------------------------------
 * Method: ip_set_common(..) 
 * Scope: Global 
 *
 * Sets attributes of the IP headers shared by all the IP packets. 
 *
 ---------------------------------------------------------------------*/
void ip_set_common(
        sr_ip_hdr_t *ip_hdr, 
        unsigned int len) 
{
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = 5; /* piazza #69 depreciated field */
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = len; 
    ip_hdr->ip_id = 0; /* No need to worry about fragmentation*/
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_p = ip_protocol_icmp;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
} 


/*---------------------------------------------------------------------
 * Method: create_icmp_time_exceeded(..) 
 * Scope: Local 
 *
 * Called to create ICMP time exceeded packet. It sets attributes of 
 * all headers appropriate to them.
 *
 ---------------------------------------------------------------------*/
void create_icmp_time_exceeded(
        uint8_t* new_packet, 
        uint8_t* original_packet, 
        unsigned int len, 
        struct sr_if *out_if /* The interface to send out the packet */) 
{
    /* Initialize the original headers from the received packet */
    sr_ip_hdr_t* original_ip_hdr = (sr_ip_hdr_t*) (original_packet + sizeof(sr_ethernet_hdr_t));

    /* Initialize the new headers to send from the newly allocated packet*/
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*) new_packet; 
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (new_packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t* icmp_t3_hdr =(sr_icmp_t3_hdr_t*) (new_packet 
                                                            + sizeof(sr_ethernet_hdr_t) 
                                                            + sizeof(sr_ip_hdr_t));

    /* Set ethernet header*/
    eth_hdr->ether_type = htons(ethertype_ip);

    /* Set IP header */
    ip_hdr->ip_dst = original_ip_hdr->ip_src;
    ip_hdr->ip_src = out_if->ip; 
    ip_set_common(ip_hdr, htons(len - sizeof(sr_ethernet_hdr_t)));

    /* Set ICMP header */
    icmp_t3_set_common(
            icmp_t3_hdr, 
            original_ip_hdr,
            len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t), 
            icmp_time_exceeded, 
            0); 
}


/*---------------------------------------------------------------------
 * Method: create_icmp_net_unreachable(..) 
 * Scope: Local 
 *
 * Called to create ICMP net unreachable packet. It sets attributes of 
 * all headers appropriate to them.
 *
 ---------------------------------------------------------------------*/
void create_icmp_net_unreachable(
        uint8_t *new_packet, 
        uint8_t *original_packet, 
        unsigned int len, 
        struct sr_if* out_if) 
{
    /* Initialize the original headers from the received packet */
    sr_ip_hdr_t* original_ip_hdr = (sr_ip_hdr_t*) (original_packet + sizeof(sr_ethernet_hdr_t));

    /* Initialize the new headers to send from the newly allocated packet*/
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*) new_packet; 
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (new_packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t* icmp_t3_hdr =(sr_icmp_t3_hdr_t*) (new_packet + sizeof(sr_ethernet_hdr_t) 
                                    + sizeof(sr_ip_hdr_t));


    /* Set ethernet header*/
    eth_hdr->ether_type = htons(ethertype_ip);

    /* Set IP header */
    ip_hdr->ip_dst = original_ip_hdr->ip_src;
    ip_hdr->ip_src = out_if->ip; 
    ip_set_common(ip_hdr, htons(len - sizeof(sr_ethernet_hdr_t)));

    /* Set ICMP header */
    icmp_t3_set_common(
            icmp_t3_hdr, 
            original_ip_hdr, 
            len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t), 
            icmp_destination_unreachable, 
            net_unreachable); 
}


/*---------------------------------------------------------------------
 * Method: create_icmp_port_unreachable(..) 
 * Scope: Local 
 *
 * Called to create ICMP port unreachable packet. It sets attributes of 
 * all headers appropriate to them.
 *
 ---------------------------------------------------------------------*/
void create_icmp_port_unreachable(
        uint8_t *new_packet, 
        uint8_t *original_packet, 
        unsigned int len) 
{
    /* Initialize the original headers from the received packet */
    sr_ip_hdr_t* original_ip_hdr = (sr_ip_hdr_t*) (original_packet + sizeof(sr_ethernet_hdr_t));

    /* Initialize the new headers to send from the newly allocated packet*/
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*) new_packet; 
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (new_packet 
                                           + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t* icmp_t3_hdr =(sr_icmp_t3_hdr_t*) (new_packet 
                                                        + sizeof(sr_ethernet_hdr_t) 
                                                        + sizeof(sr_ip_hdr_t));

    /* Set ethernet header*/
    eth_hdr->ether_type = htons(ethertype_ip);

    /* Set ip header */
    ip_hdr->ip_dst = original_ip_hdr->ip_src;
    ip_hdr->ip_src = original_ip_hdr->ip_dst;
    ip_set_common(ip_hdr, htons(len - sizeof(sr_ethernet_hdr_t)));

    /* Set icmp header */
    icmp_t3_set_common(
            icmp_t3_hdr, 
            original_ip_hdr, 
            len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t), 
            icmp_destination_unreachable, 
            port_unreachable); 
}


/*---------------------------------------------------------------------
 * Method: create_icmp_echo_reply(..) 
 * Scope: Local 
 *
 * Called to create reply packet to ICMP echo request. It sets attributes of 
 * all headers appropriate to them.
 *
 ---------------------------------------------------------------------*/
void create_icmp_echo_reply(
        uint8_t *new_packet, 
        uint8_t *original_packet, 
        unsigned int len) 
{
    /* Initiate the headers from echo request packet to copy.*/
    sr_ip_hdr_t *original_ip_hdr = (sr_ip_hdr_t *) (original_packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_hdr_t* original_icmp_hdr = (sr_icmp_hdr_t*) (original_packet 
                                                         + sizeof(sr_ethernet_hdr_t) 
                                                         + sizeof(sr_ip_hdr_t));
    

    /* Initiate the headers for the echo reply packet to be sent.*/
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*) new_packet; 
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (new_packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_hdr_t* icmp_hdr =(sr_icmp_hdr_t*) (new_packet 
                                               + sizeof(sr_ethernet_hdr_t) 
                                               + sizeof(sr_ip_hdr_t));

    /* Set the ethernet header. */
    eth_hdr->ether_type = htons(ethertype_ip);

    /* Set the ip fields */
    ip_hdr->ip_src = original_ip_hdr->ip_dst;
    ip_hdr->ip_dst = original_ip_hdr->ip_src;
    ip_set_common(ip_hdr, htons(len - sizeof(sr_ethernet_hdr_t))); 
   
    /* Set the icmp fields */
    memcpy(icmp_hdr, original_icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_type = icmp_echo_reply;
    icmp_hdr->icmp_code = 0; /* No code */ 
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

}


/*---------------------------------------------------------------------
 * Method: sr_handle_arp(..) 
 * Scope: Global 
 *
 * Called if the received packet is an ARP packet. It then handles the 
 * ARP packet.
 *
 ---------------------------------------------------------------------*/
void sr_handle_arp(struct sr_instance* sr,
        uint8_t* packet, 
        unsigned int len,
        char* interface /* lent */)
{
    /* Initialize ARP packet from the received packet */
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

    /* Sanity check on the received ARP packet */
    if (arp_sanity_check(arp_hdr, len - sizeof(sr_ethernet_hdr_t)) == 1) {
        fprintf(stderr, "Failed sanity check.\n");
        return;
    }

    /* Check if the received ARP packet was for this router. */
    struct sr_if *target_if = sr_get_interface_from_ip(sr, arp_hdr->ar_tip);
    
    /* The ARP packet destined for this router */
    if (target_if) {
        
        /* The ARP packet is an ARP request packet */
        if (ntohs(arp_hdr->ar_op) == arp_op_request) {
            printf("ARP request.\n");
            
            /* Create new ARP reply packet to send back to the sender of the request */
            int new_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
            uint8_t *new_packet = malloc(new_packet_len);
            if (new_packet == NULL) {
                fprintf(stderr, "Failed to allocate memory for the ARP reply packet.\n");
                return;
            }

            create_arp_reply(new_packet, arp_hdr, target_if);
            
            sr_send_packet(sr, new_packet, new_packet_len, target_if->name);
             
            free(new_packet);
            return;
        }
        
        /* The ARP packet is an ARP reply packet */
        else if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
            printf("ARP reply.\n");
            
            /* Cache the MAC address indicated on the reply */
            struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
            
            /* Send out all the outstanding packets destined for this MAC address' interface */
            if (req) {
                struct sr_packet *req_packet;
                for (req_packet = req->packets; req_packet; req_packet = req_packet->next) {
                    send_outstanding_packet(sr, arp_hdr, req_packet);
                }
            }
            
            /* Destroy the cache associated with the request that is replied */
            sr_arpreq_destroy(&(sr->cache) ,req);
            
            return;
        }
    }
    
    /* The ARP packet not for this router */
    else {
        fprintf(stderr, "The ARP packet not for this router.\n");
        return;
    }
}


/*---------------------------------------------------------------------
 * Method: sr_handle_ip(..) 
 * Scope: Global 
 *
 * Called if the received packet is an IP packet. It then handles the 
 * IP packet.
 *
 ---------------------------------------------------------------------*/
void sr_handle_ip(struct sr_instance* sr,
        uint8_t* packet, 
        unsigned int len,
        char* interface/* lent */)
{
    /* Initialize IP packet from received packet */
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));

    /* The sanity check on the IP packet */
    if (ip_sanity_check(ip_hdr, len - sizeof(sr_ethernet_hdr_t)) == 1) { 
        fprintf(stderr, "Failed sanity check.\n"); 
        return;
    }

    /* Check if the received IP packet was for this router */
    struct sr_if* matched_if = sr_get_interface_from_ip(sr, ip_hdr->ip_dst); 

    /* The packet is destined for this router */
    if (matched_if) {

        /* The packet is ICMP packet */
        if (ip_hdr->ip_p == ip_protocol_icmp) {
            sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *) (packet 
                                                         + sizeof(sr_ethernet_hdr_t) 
                                                         + sizeof(sr_ip_hdr_t));
            
            /* Sanity check on the ICMP packet */
            if (icmp_sanity_check(icmp_hdr, ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t)) == 1) {
                fprintf(stderr, "Failed sanity check.\n");
                return;
            }

            /* The ICMP packet is echo request packet */
            if (icmp_hdr->icmp_type == icmp_echo_request) {
                
                /* Creates the echo reply packet and sent back  */
                uint8_t *new_packet = malloc(len);
                if (packet == NULL) {
                    perror("Failed to allocate space for ICMP reply packet.\n");
                    return;
                }
                
                /* Use longest prefix match to find out which interface it should send back the packet */
                struct sr_rt *out_rt_entry = longest_prefix_match(sr, ip_hdr->ip_src);
                if (out_rt_entry == NULL) {
                    fprintf(stderr, "Failed to match the interface to send outstanding packets.\n");
                    free(new_packet);
                    return;
                }
                struct sr_if* out_if = sr_get_interface(sr, out_rt_entry->interface);
                
                create_icmp_echo_reply(new_packet, packet, len); 
                
                /* Send to the next hop point using ARP cache */
                send_to_next_hop(sr, new_packet, len, ip_hdr->ip_src, out_if);

                free(new_packet);

            } else {
                printf("Unvalid ICMP type.\n");
            }
        }
        
        /* The received packet is UDP/TCP. */
        else if (ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp) {
            fprintf(stderr, "TCP/UDP packet to the router. %s.\n", matched_if->name);

            /* Create ICMP port unreachable packet and send back to the sender */
            size_t new_packet_len = sizeof(sr_ethernet_hdr_t) 
                                      + sizeof(sr_ip_hdr_t) 
                                      + sizeof(sr_icmp_t3_hdr_t);
            
            uint8_t *new_packet = malloc(new_packet_len);
            if (new_packet == NULL) {
                perror("Failed to allocate space for ICMP packet.\n");
                return;
            } 

            /* Use longest prefix match to find out which interface it should send back the packet */
            struct sr_rt *out_rt_entry = longest_prefix_match(sr, ip_hdr->ip_src);
            if (out_rt_entry == NULL) {
                fprintf(stderr, "Failed to match the interface to send back time exceeded error.\n");
                free(new_packet);
                return;
            }
            
            struct sr_if* out_if= sr_get_interface(sr, out_rt_entry->interface);
            
            create_icmp_port_unreachable(new_packet, packet, new_packet_len);

            /* Send to the next hop point using ARP cache */
            send_to_next_hop(sr, new_packet, new_packet_len, ip_hdr->ip_src, out_if);

            free(new_packet);
            return;

        }
        else {
            fprintf(stderr, "unvalid packet.\n");
            return;
        }
    }

    /* IP packet not destined for this router */
    else {
        /* Use the longest prefix match to find the next hop point */
        struct sr_rt* lpm_if = longest_prefix_match(sr, ip_hdr->ip_dst); 
        
        /* The next hop found */
        if (lpm_if) {
            /* Check Time To Leave and make decision based on its value*/
            if (ttlcheck_and_checksum(ip_hdr) == 0) {
                send_to_next_hop(sr, 
                                 packet, 
                                 len, 
                                 ip_hdr->ip_dst, 
                                 sr_get_interface(sr, lpm_if->interface));
            } 
            /* Time To Live expired. Send back the time exceeded packet back to the sender */
            else {
                size_t icmp_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) 
                                         + sizeof(sr_icmp_t3_hdr_t);
                
                uint8_t *icmp_packet = malloc(icmp_packet_len); 
                if (icmp_packet == NULL) {
                    perror("Failed to allocate space for ICMP packet.\n");
                    return;
                } 
                
                /* Use longest prefix match to find out which interface it should send back the packet */
                struct sr_rt *out_rt_entry = longest_prefix_match(sr, ip_hdr->ip_src);
                if (out_rt_entry == NULL) {
                    fprintf(stderr, "Failed to match the interface to send back time exceeded error.\n");
                    free(icmp_packet);
                    return;
                }
                struct sr_if* out_if= sr_get_interface(sr, out_rt_entry->interface);

                create_icmp_time_exceeded(icmp_packet, packet, icmp_packet_len, out_if); 
                
                /* Send to the next hop point using ARP cache */
                send_to_next_hop(sr, icmp_packet, icmp_packet_len, ip_hdr->ip_src, out_if);
                
                free(icmp_packet);
            }
        }
        
        /* The next hop cannot be found */
        else {
            
            /* Send back ICMP net unreachable packet back to source of the received packet */
            size_t icmp_packet_len = sizeof(sr_ethernet_hdr_t) 
                                     + sizeof(sr_ip_hdr_t) 
                                     + sizeof(sr_icmp_t3_hdr_t);
            uint8_t *icmp_packet = malloc(icmp_packet_len);
            if (icmp_packet == NULL) {
                perror("Failed to allocate space for ICMP packet.\n");
                return;
            } 
            
            /* Use longest prefix match to find out which interface it should send back the packet */
            struct sr_rt *out_rt_entry = longest_prefix_match(sr, ip_hdr->ip_src);
            if (out_rt_entry == NULL) {
                fprintf(stderr, "Failed to match the interface to send back Net Unreachable error.\n");
                free(icmp_packet);
                return;
            }
            struct sr_if *out_if = sr_get_interface(sr, out_rt_entry->interface); 
            
            create_icmp_net_unreachable(icmp_packet, packet, icmp_packet_len, out_if);
            
            /* Send to the next hop point using ARP cache */
            send_to_next_hop(sr, icmp_packet, icmp_packet_len, ip_hdr->ip_src, out_if);

            free(icmp_packet);
            return;
        }
    }
}



/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/
void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);


  printf("*** -> Received packet of length %d \n",len);
  /* fill in code here */
    if (len < sizeof(sr_ethernet_hdr_t)) {
        fprintf(stderr, "Ethernet packet shorter than minimum length - len: %u.\n", len);
        return;
    }

    uint16_t eth_t = ethertype(packet);

    /* handle the data*/
    if (eth_t == ethertype_arp) {   /* data is ARP packet */
        printf("ARP packet received.\n");
        sr_handle_arp(sr, packet, len, interface);
    }
    else if (eth_t == ethertype_ip) {   /* data is IP packet */
        printf("IP packet received.\n");
        sr_handle_ip(sr, packet, len, interface);
    } 
}/* end sr_ForwardPacket */

