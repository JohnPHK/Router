#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_rt.h"



/*---------------------------------------------------------------------
 * Method: create_icmp_host_unreachable(..) 
 * Scope: Local 
 *
 * Called to create ICMP host unreachable packet. It sets attributes of 
 * all headers appropriate to them.
 *
 ---------------------------------------------------------------------*/
void create_icmp_host_unreachable(
        uint8_t *new_packet, 
        uint8_t *original_packet, 
        unsigned int len, 
        struct sr_if *out_if /* The interface to send out the packet */) 
{    
    sr_ip_hdr_t *original_ip_hdr = (sr_ip_hdr_t *) (original_packet + sizeof(sr_ethernet_hdr_t));
    
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*) new_packet; 
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (new_packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t* icmp_t3_hdr =(sr_icmp_t3_hdr_t*) (new_packet 
                                               + sizeof(sr_ethernet_hdr_t) 
                                               + sizeof(sr_ip_hdr_t));
    /* Set up ethernet header */
    eth_hdr->ether_type = htons(ethertype_ip);
    
    /* Set ip header */
    ip_hdr->ip_dst = original_ip_hdr->ip_src;
    ip_hdr->ip_src = out_if->ip;
    ip_set_common(ip_hdr, len - sizeof(sr_ethernet_hdr_t));
    
    /* Set icmp header */
    icmp_t3_set_common(
            icmp_t3_hdr, 
            original_ip_hdr, 
            len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t), 
            icmp_destination_unreachable, 
            host_unreachable); 
}


/*---------------------------------------------------------------------
 * Method: create_arp_request(..) 
 * Scope: Local 
 *
 * This method creates ARP requst packet by setting its attribute of 
 * ARP header to it appropriate values.
 *
 ---------------------------------------------------------------------*/
void create_arp_request(uint8_t *new_packet, struct sr_arpreq* req, struct sr_if *out_if)
{
    /* Initialize the variables needed */
    sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *) new_packet;
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) (new_packet + sizeof(sr_ethernet_hdr_t)); 

    /* Set up ethernet header */
    memcpy(ethernet_hdr->ether_shost, out_if->addr, ETHER_ADDR_LEN);  
    memset(ethernet_hdr->ether_dhost, 0xFF, ETHER_ADDR_LEN);
    ethernet_hdr->ether_type = htons(ethertype_arp);

    arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    arp_hdr->ar_pro = htons(protocol_ipv4);
    arp_hdr->ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ar_pln = 4; /* Google ipv4 arp header length shows 4 bytes */ 
    arp_hdr->ar_op = htons(arp_op_request); 
    memcpy(arp_hdr->ar_sha, out_if->addr, ETHER_ADDR_LEN);
    arp_hdr->ar_sip = out_if->ip;
    memset(arp_hdr->ar_tha, 0xFF, ETHER_ADDR_LEN); 
    arp_hdr->ar_tip = req->ip;

}


/*---------------------------------------------------------------------
 * Method: handle_arpreq(..) 
 * Scope: Global 
 * 
 * Handles the request packet. Ensures request packet is not sent within
 * 1 second time interval and not more than 5 times. If the request packet
 * has been sent 5 times, sends host unreachable packet back to the source.
 *
 ---------------------------------------------------------------------*/
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq* req) {
    time_t now = time(NULL);

    /* Checks if another request has been sent within a second */
    if (difftime(now, req->sent) >= 1.0) {
        
        /* The request has been sent 5 times */
        if (req->times_sent >= 5) {
            
            /* For each packet outstanding destined for this ip address, 
             * send back host unreachable packet */
            struct sr_packet *packet;
            for (packet = req->packets; packet; packet = packet->next) {
                sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*) (packet->buf + sizeof(sr_ethernet_hdr_t));
                
                int new_packet_len = sizeof(sr_ethernet_hdr_t) 
                                      + sizeof(sr_ip_hdr_t) 
                                      + sizeof(sr_icmp_t3_hdr_t);
                uint8_t *new_packet = malloc(new_packet_len);
                if (new_packet == NULL) {
                    perror("Failed to allocate space for the ICMP packet.\n");
                    return;
                }
                memset(new_packet, 0, new_packet_len);
                
                /* Use longest prefix match to find out which interface it should send back the packet */
                struct sr_rt *out_rt_entry = longest_prefix_match(sr, ip_hdr->ip_src);
                if (out_rt_entry == NULL) {
                    fprintf(stderr, "Failed to match the interface to send back time exceeded error.\n");
                    free(new_packet);
                    return;
                }
                struct sr_if *out_if = sr_get_interface(sr, out_rt_entry->interface);
                
                create_icmp_host_unreachable(new_packet, packet->buf, new_packet_len, out_if);

                send_to_next_hop(sr, new_packet, new_packet_len, ip_hdr->ip_src, out_if);
                
                free(new_packet);
            }
            sr_arpreq_destroy(&sr->cache, req);
        }
        
        /* The reply to the request has not been received and it has not been sent 5 times */
        else {
            
            /* Creates ARP request packet and send through proper interface to destination */
            int new_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
            uint8_t *new_packet = malloc(new_packet_len);
            if (new_packet == NULL) {
                perror("Failed to allocate space to send out ARP request.\n");
                return;
            }
            memset(new_packet, 0, new_packet_len); 

            struct sr_if* out_if = sr_get_interface(sr, req->packets->iface);
            
            create_arp_request(new_packet, req, out_if);

            sr_send_packet(sr, new_packet, new_packet_len, out_if->name);

            free(new_packet);

            req->sent = now;
            req->times_sent++;
        }
    }
}


/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    /* Fill this in */
    /* Loops over all outstanding requests and handles it */
    struct sr_arpreq *walker;
    for (walker = sr->cache.requests; walker; walker = walker->next) {
        handle_arpreq(sr, walker); 
    }
}



/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

