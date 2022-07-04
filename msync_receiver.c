/*!
 * Msync Validator Receiver
 * https://github.com/Broadpeak-tv/Msync_validator_receiver.git
 * Copyright © 2022 Broadpeak, S.A. 
 * All Rights Reserved.
 * 
 * This code is licensed under the Apache License, Version 2.0 (the "License").
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <stdbool.h>
#ifdef TARGETOS_eCos
#include <sys/socket.h>                          /* Must be before netinet/in.h */
#include <netinet/in.h>                          /* Must be before arpa/inet.h */
#include <net/netdb.h>                           /* for inet_ntop() family, includes netinet/in.h */
#endif
#if defined HAVE_GETIFADDRS
#include <ifaddrs.h>
#endif
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#define MIN(a,b) (((a)<(b))?(a):(b))

#include "rtp_header.h"
#include "msync_protocol.h"

#define MSYNC_CLIENT_NAME     "msync_receiver"
#define MSYNC_CLIENT_VERSION  "3"
#define MSYNC_DEFAULT_PORT    6044
#define MSYNC_DEFAULT_LAYERS  1
#define MSYNC_MAX_LAYERS      10

static int verbose = 0;

/* 
 * Use RTP as part of the transport multicast session protocol ? 
 */
static bool rtp = false;

/*
 * This is usally defined in <symcat.h> which isn't available in uclibc
 */
#define STRINGX(s) #s
#define XSTRING(s) STRINGX(s)

#define HASHSIZE 101

/* packet list to remember which packets have been received*/
typedef struct plist { /* table entry: */
    struct plist *next; /* next entry in chain */
	uint32_t offset;
} plist_t;

typedef struct object_descriptor { 
	uint32_t size;                 	/*!< Object size in bytes */
	uint32_t packets;              	/*!< Number of MSync packets the object is broken up into */
	uint32_t crc;                  	/*!< object CRC */
	uint8_t  otype;                	/*!< object type (one of MSYNC_OBJECT_TYPE_* ) */
	uint8_t mtype;					/*!< Manifest type (4 first bits)*/
	uint16_t uri_size;       		/*!< size of the URI */
	uint32_t media_sequence;  	   	/*!< Media sequence number*/
	char uri[MSYNC_URI_LENGTH_MAX]; /*!< URI */
	struct plist *hashtab[HASHSIZE]; 		/*!< received packets */
	uint32_t recvd_uniq_packets;    /*!< Number of unique packts received */
    FILE *fptr; /* file pointer */
	bool received_object_info_before_data; 
} object_descriptor_t ;


/*
 * Object list used to store object structs
 */
typedef struct olist { /* table entry: */
    struct olist *next; /* next entry in chain */
	uint16_t oid;       /*!< object id */
	object_descriptor_t *obj; /* pointer to object struct */
} olist_t;

static olist_t *hashtab[HASHSIZE]; /* pointer table of object descriptors */

/* 
 * hash: form hash value for uint16_t 
 * based on Thomas Wang: https://burtleburtle.net/bob/hash/integer.html
*/
unsigned hash16(uint16_t id)
{
    unsigned hashval = id;
	hashval += ~(hashval << 15);
	hashval ^= (hashval >> 10);
	hashval += (hashval << 3);
	hashval ^= (hashval >> 6);
	hashval += ~(hashval << 11);
	hashval ^= (hashval >> 16);
    return hashval % HASHSIZE;
}

/* 
 * hash: form hash value for uint32_t 
 * based on Thomas Wang: https://burtleburtle.net/bob/hash/integer.html
*/
unsigned hash32(uint32_t id)
{
    unsigned hashval = id;
    hashval = (hashval+0x7ed55d16) + (hashval<<12);
    hashval = (hashval^0xc761c23c) ^ (hashval>>19);
    hashval = (hashval+0x165667b1) + (hashval<<5);
    hashval = (hashval+0xd3a2646c) ^ (hashval<<9);
    hashval = (hashval+0xfd7046c5) + (hashval<<3);
    hashval = (hashval^0xb55a4f09) ^ (hashval>>16);
    return hashval % HASHSIZE;
}


/* lookup: look for oid in hashtab */
plist_t *lookup_packet(uint32_t offset, plist_t **phashtab)
{
    plist_t *np = NULL;
    for (np = phashtab[hash32(offset)]; np != NULL; np = np->next)
        if (np != NULL && offset == np->offset)
          return np; /* found */
    return NULL; /* not found */
}

plist_t *put_packet(uint32_t offset, plist_t **phashtab)
{
    plist_t *np = NULL;
    unsigned hashval;
    if ((np = lookup_packet(offset, phashtab)) == NULL) { /* not found */
        np = (struct plist *) malloc(sizeof(*np));
        if (np == NULL)
          return NULL;
		np->offset = offset;
        hashval = hash32(offset);
        np->next = phashtab[hashval];
        phashtab[hashval] = np;
    }
    return np;
}

void release_packet_hashtab(plist_t **phashtab){
	plist_t *np = NULL;
	int i=0;
	for (i=0; i < HASHSIZE; i++) {
		np = phashtab[i];
		while(np != NULL) {
			plist_t *np_free = np;
			np = np->next;
			free(np_free);
		}
	}
    
}


void release_object(uint16_t oid){
    olist_t *np = NULL;
	olist_t *np_prev = NULL;
    for (np = hashtab[hash16(oid)]; np != NULL; np = np->next) {
        if (oid == np->oid) { /* found */
			if (np_prev != NULL)
				np_prev->next = np->next;
			release_packet_hashtab(np->obj->hashtab);
			free(np->obj);
			free(np);
			break; 
		}
		np_prev = np;
	}

}

/* lookup: look for oid in hashtab */
olist_t *lookup_object(uint16_t oid)
{
    olist_t *np = NULL;
    for (np = hashtab[hash16(oid)]; np != NULL; np = np->next)
        if (np != NULL && oid == np->oid)
          return np; /* found */
    return NULL; /* not found */
}

olist_t *put_object(uint16_t oid, object_descriptor_t *obj)
{
    olist_t *np = NULL;
    unsigned hashval;
    if ((np = lookup_object(oid)) == NULL) { /* not found */
        np = (struct olist *) malloc(sizeof(*np));
        if (np == NULL)
          return NULL;
        hashval = hash16(oid);
        np->next = hashtab[hashval];
        hashtab[hashval] = np;
    }
	np->oid = oid;
    np->obj = obj;
    return np;
}



/*
 * usage()
 */
#ifndef TARGETOS_eCos
static void usage(void)
{
	printf(
		MSYNC_CLIENT_NAME " of msync protocol v" MSYNC_CLIENT_VERSION "\n"
		"   Usage: " MSYNC_CLIENT_NAME " [-m multicast_address] <-r> <-l num_layers> <-p port> <-i interface_name> <-v>\n"
		"       -m  Multicast IP address to receive MSync packet from\n"
		"       -r  Use RTP as part of the transport multicast session protocol (default: no RTP)\n"		
		"       -l  How many \"layers\", e.g. multicast addresses, to receive (default " XSTRING(MSYNC_DEFAULT_LAYERS) ", up to " XSTRING(MSYNC_MAX_LAYERS)")\n"
		"           IP addresses are incremented by one for each layer\n"
		"       -p  Multicast port (default " XSTRING(MSYNC_DEFAULT_PORT)")\n"
		"       -i  Network interface to bind to\n"
		"       -v  Verbose mode\n"
		"\n");
}
#endif

#if defined HAVE_GETIFADDRS
static char * get_interface_address(char * iname)
{
	unsigned int bfound = 0;
	char * ip_str = NULL;
	struct ifaddrs* if_addresses = NULL;
	struct ifaddrs* ifa = NULL;

	/* NB: for test purpose, return only the first found address!
	 * Need to be modified if we want every address of the interface */

	if (getifaddrs(&if_addresses) == 0)
	{
		ifa = if_addresses;
		while ((ifa != NULL)&&(bfound == 0))
		{
			if (strncmp(ifa->ifa_name, iname, strlen(iname)) == 0)
			{
				if (ifa->ifa_addr == NULL)
				{
					printf("Null address for interface %s", iname);
				} else if (ifa->ifa_addr->sa_family == AF_INET)
				{
					ip_str = (char*) malloc(INET_ADDRSTRLEN);

					if (inet_ntop(AF_INET, (void*) &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr, ip_str, INET_ADDRSTRLEN) != NULL) {
						/* Record address */
					        bfound = 1;
						printf("Found IPv4 address %s, on interface %s\n", ip_str, iname);
					} else
					{
						free(ip_str);
						ip_str = NULL;
						printf("Error converting IPv4 address ");
					}
				} else if (ifa->ifa_addr->sa_family == AF_INET6)
				{
					ip_str = (char*) malloc(INET6_ADDRSTRLEN);

					if (inet_ntop(AF_INET6, (void*) &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr, ip_str, INET6_ADDRSTRLEN) != NULL)
					{
						/* Record address */
					        bfound = 1;
						printf("Found IPv6 address %s, on interface %s\n", ip_str, iname);
					} else
					{
						free(ip_str);
						ip_str = NULL;
						printf("Error converting IPv6 address ");
					}
				}
			}
			ifa = ifa->ifa_next;
		}
	}
	if (if_addresses != NULL)
	{
		freeifaddrs(if_addresses);
	}
	return ip_str;
}
#endif

//#define DEBUG_GENERATE_IGMP_REPORT 1
#ifdef DEBUG_GENERATE_IGMP_REPORT
static void send_raw_igmp_report(in_addr_t ip_addr /* Network format */)
{
	/* Send a Join IGMP  frame */
	int bytesSent = 0;
	int i;
	int iSock;
	short sCheckSum;
	struct
	{
		unsigned int  uiType:8;
		unsigned int  uiMaxRespTime:8;
		unsigned int  uiCheckSum:16;
		unsigned int  uiGrpAddr:32;
	} stIgmp;
	memset(&stIgmp, 0, sizeof(stIgmp));
	stIgmp.uiCheckSum = 0;
	stIgmp.uiType=0x16;
	stIgmp.uiMaxRespTime = 0;
	stIgmp.uiGrpAddr = ip_addr;

	sCheckSum = 0;
	for(i=0; i < 4; i++)
	{
		sCheckSum +=((unsigned short*)&stIgmp)[i];
	}
	stIgmp.uiCheckSum = 0XFFFF-sCheckSum;

	printf("Prepare Buffer of %d Byte into Raw Socket : %02X %02X %02X %02X %02X %02X %02X %02X\n", sizeof(stIgmp),
			((unsigned char*)&stIgmp)[0], ((unsigned char*)&stIgmp)[1], ((unsigned char*)&stIgmp)[2], ((unsigned char*)&stIgmp)[3],
			((unsigned char*)&stIgmp)[4], ((unsigned char*)&stIgmp)[5], ((unsigned char*)&stIgmp)[6], ((unsigned char*)&stIgmp)[7]);

	iSock = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP);
	if (iSock !=1)
	{
		printf("Send %d Byte into Raw Socket : %02X %02X %02X %02X %02X %02X %02X %02X\n", sizeof(stIgmp),
				((unsigned char*)&stIgmp)[0], ((unsigned char*)&stIgmp)[1], ((unsigned char*)&stIgmp)[2], ((unsigned char*)&stIgmp)[3],
				((unsigned char*)&stIgmp)[4], ((unsigned char*)&stIgmp)[5], ((unsigned char*)&stIgmp)[6], ((unsigned char*)&stIgmp)[7]);
		bytesSent = sendto(iSock, &stIgmp, sizeof(stIgmp), 0, (struct sockaddr*)&sa_in,sa_in_len);
		printf("Send result %d\n", bytesSent);
		close(iSock);
	}
	else
	{
		printf("Open Socket RAW Fail error %d\n", errno);
	}
}
#endif

/*
 * Open and bind an IPv4 datagram socket (IP and port must be in network byte order)
 */
static int open_socket(char * iname, in_addr_t ip_addr, in_port_t port)
{
	int sd;
	socklen_t sa_in_len = sizeof(struct sockaddr_in);
	struct sockaddr_in sa_in =
	{
		.sin_family = AF_INET,
		.sin_addr.s_addr = ip_addr,
		.sin_port = port
	};
	int reuseAddr = 1;

	printf("Opening datagram socket\n");

	if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		perror("Error opening datagram socket");
		return -1;
	}

	printf("Setting option REUSEADDR\n");

	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &reuseAddr, sizeof(reuseAddr)) !=0)
	{
		perror("setsockopt SO_REUSEADDR error");
		close(sd);
		return -1;
	}

	printf("Binding\n");

	if (bind(sd, (struct sockaddr*) &sa_in, sa_in_len) < 0)
	{
		perror("bind error");
		close(sd);
		return -1;
	}

	if (IN_MULTICAST(ntohl(ip_addr)))
	{
#ifdef HAVE_IP_MREQN
		struct ip_mreqn mreq;
		uint32_t iface;
#else
		struct ip_mreq mreq;
#endif
		socklen_t mreq_len = sizeof(mreq);

		memset(&mreq, 0, mreq_len);

#ifdef HAVE_IP_MREQN
		if ((iface = if_nametoindex(iname)) == 0)
		{
			perror("Error converting interface name");
			close(sd);
			return -1;
		}
		mreq.imr_ifindex = (int) if_index;
		mreq.imr_address.s_addr = htonl(INADDR_ANY);
#else
# if defined HAVE_GETIFADDRS
		char * ip_str = get_interface_address(iname);
		in_addr_t  stAddr = INADDR_ANY;
		if (ip_str != NULL)
		{
			if (inet_pton(AF_INET, ip_str, (void*) &stAddr) == 1)
			{
				mreq.imr_interface.s_addr = stAddr;
				free(ip_str);
			}
			else
			{
				printf("Error during inet_pton\n");
				free(ip_str);
				close(sd);
				return -1;
			}
		}
		else
		{
			printf("Null pointer returned by get_interface_address\n");
			close(sd);
			return -1;
		}
# else
		mreq.imr_interface.s_addr = htonl(INADDR_ANY); /* TODO if necessary: Use ioctl to retrieve address of the interface */
# endif
#endif
		mreq.imr_multiaddr.s_addr = ip_addr;

		printf("Join multicast (imr_interface.s_addr 0x%08x, imr_multiaddr.s_addr 0x%08x)\n", mreq.imr_interface.s_addr, mreq.imr_multiaddr.s_addr);

		if (setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, mreq_len) < 0)
		{
			perror("Error joining multicast group");
			close(sd);
			return -1;
		}
	}
	else
	{
		printf("Warning: %s is not a multicast IP address\n", inet_ntoa(sa_in.sin_addr));
	}

	printf("Socket #%d listening on %s:%u\n", sd, inet_ntoa(sa_in.sin_addr), ntohs(sa_in.sin_port));

	return sd;
}


/*
 * Close a socket
 */
static int close_socket(int sd, char * iname, in_addr_t ip_addr)
{
	if (IN_MULTICAST(ntohl(ip_addr)))
	{
#ifdef HAVE_IP_MREQN
		struct ip_mreqn mreq;
		uint32_t iface;
#else
		struct ip_mreq mreq;
#endif
		socklen_t mreq_len = sizeof(mreq);

		memset(&mreq, 0, mreq_len);

#ifdef HAVE_IP_MREQN
		if ((iface = if_nametoindex(iname)) == 0)
		{
			perror("Error converting interface name");
			close(sd);
			return -1;
		}
		mreq.imr_ifindex = (int) if_index;
		mreq.imr_address.s_addr = htonl(INADDR_ANY);
#else
# if defined HAVE_GETIFADDRS
		char * ip_str = get_interface_address(iname);
		in_addr_t  stAddr = INADDR_ANY;
		if (ip_str != NULL)
		{
			if (inet_pton(AF_INET, ip_str, (void*) &stAddr) == 1)
			{
				mreq.imr_interface.s_addr = stAddr;
				free(ip_str);
			}
			else
			{
				printf("Error during inet_pton\n");
				free(ip_str);
				close(sd);
				return -1;
			}
		}
		else
		{
			printf("Null pointer returned by get_interface_address\n");
			close(sd);
			return -1;
		}
# else
		mreq.imr_interface.s_addr = htonl(INADDR_ANY); /* TODO if necessary: Use ioctl to retrieve address of the interface */
# endif
#endif
		mreq.imr_multiaddr.s_addr = ip_addr;
		if (setsockopt(sd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, mreq_len) < 0)
		{
			perror("Error leaving multicast group");
			close(sd);
			return -1;
		}
	}

	close(sd);
	printf("Socket #%d closed\n", sd);

	return 0;
}


const char pathSeparator =
#ifdef _WIN32
  '\\';
#else
  '/';
#endif

// Given a file path, create all constituent directories if missing
void create_file_path_dirs(char *file_path) {
  char *dir_path = (char *) malloc(strlen(file_path) + 1);
  char *next_sep = strchr(file_path, pathSeparator);
  while (next_sep != NULL) {
    int dir_path_len = next_sep - file_path;
    memcpy(dir_path, file_path, dir_path_len);
    dir_path[dir_path_len] = '\0';
    mkdir(dir_path, S_IRWXU|S_IRWXG|S_IROTH);
    next_sep = strchr(next_sep + 1, pathSeparator);
  }
  free(dir_path);
}

/*
 * MSync receiver
 */
static void msync_receiver_cleanup(void* arg)
{
	uint8_t* packet = (uint8_t*) arg;

	free(packet);
}

static void* msync_receiver(void* arg)
{
	int* sd = (int*) arg;
	uint8_t* packet = NULL;
	ssize_t len;
	rtp_hdr_t* rtp_h;
	msync_header_t* msync_h;
	msync_oinfo_header_t* oinfo_h;
	msync_odata_header_t* odata_h;
	msync_ohttp_header_t* ohttp_h;
	msync_odata_part_header_t* odata_part_h;
	int rtp_prev_seq = -1;

	if (!(packet = (uint8_t*) malloc(MSYNC_PAYLOAD_MTU_MAX)))
	{
		printf("malloc failure\n");
		return NULL;
	}
	pthread_cleanup_push(msync_receiver_cleanup, (void*) packet);

	if (rtp) {
		rtp_h = (rtp_hdr_t*) packet;
		msync_h = (msync_header_t*) (packet + RTP_HEADER_LEN);
	} else {
		msync_h = (msync_header_t*) packet;
	}
	oinfo_h = (msync_oinfo_header_t*) (msync_h);
	odata_h = (msync_odata_header_t*) (msync_h);
	ohttp_h = (msync_ohttp_header_t*) (msync_h);
	odata_part_h = (msync_odata_part_header_t*) (msync_h);	

	while (1)
	{
#ifndef TARGETOS_eCos
		if ((len = read(*sd, packet, MSYNC_PAYLOAD_MTU_MAX)) <= 0)
#else
		if ((len = recv(*sd, packet, MSYNC_PAYLOAD_MTU_MAX, 0)) <= 0)
#endif
		{
			if (errno == EINTR)
			{
				continue;
			}
			break;
		}
		if (rtp && len >= RTP_HEADER_LEN)
		{
			if (rtp_prev_seq > 0)
			{
				if (ntohs(rtp_h->seq) != (uint16_t)(rtp_prev_seq + 1))
				{
					printf("%d RTP: missing seq: 0x%04X\n", *sd, rtp_prev_seq + 1);
				}
			}
			rtp_prev_seq = ntohs(rtp_h->seq);
		}
		if ((rtp && len >= RTP_HEADER_LEN + MSYNC_HEADER_LEN) || (!rtp && len >= MSYNC_HEADER_LEN))
		{
			if (verbose)
			{
				printf(" %d Msync Header\t: version: %d, type %d, object id: 0x%04X\n", *sd, msync_h->version, msync_h->type, ntohs(msync_h->object_id));
			}
			if (msync_h->version!=0x03) {
				printf("MSYNC version %d not supported\n",msync_h->version);
				continue;
			}

			/* malloc empty object descr if not already existing */
			olist_t *np ;
			if ((np = lookup_object(ntohs(msync_h->object_id)))==NULL) {
				object_descriptor_t * obj_descr = (object_descriptor_t *) calloc(1, sizeof(object_descriptor_t));
				np = put_object(ntohs(msync_h->object_id), obj_descr);
			}

			/* Object Info Packet Header */
			if (msync_h->version==0x03 && ((msync_h->type == MSYNC_TYPE_OINFO) ||
					(msync_h->type == MSYNC_TYPE_OINFO_CHECK)))
			{
				uint8_t mtype = ntohs(oinfo_h->mtype_uri_size) >> 12;
				uint16_t uri_size = ntohs(oinfo_h->mtype_uri_size) & 0x0FFF;
				oinfo_h->uri[MIN(uri_size, MSYNC_URI_LENGTH_MAX - 1)] = '\0';
				if (verbose)
					printf("  %d %s: %u bytes in %u packets (CRC 0x%08X) - type: %s, manifest type: %s, uri size: %u, media_seq: %u, uri: %s\n",
							*sd, 
							msync_h->type == MSYNC_TYPE_OINFO ? "Object Info\t" : "Object Info Redundancy\t",
							ntohl(oinfo_h->size), 
							ntohl(oinfo_h->packets), 
							ntohl(oinfo_h->crc),
							oinfo_h->otype == MSYNC_OBJECT_TYPE_MANIFEST ? "Manifest" :
								oinfo_h->otype ==  MSYNC_OBJECT_TYPE_RESERVED ? "Reserved" :
									oinfo_h->otype == MSYNC_OBJECT_TYPE_MEDIA_MPEG2TS ? "MPEG2TS" : 
										oinfo_h->otype == MSYNC_OBJECT_TYPE_MEDIA_CMAF ? "CMAF" :
											oinfo_h->otype == MSYNC_OBJECT_TYPE_CONTROL ? "CONTROL" : "unknown",
							mtype == MSYNC_MANIFEST_NA ? "NA" :
								mtype ==  MSYNC_MANIFEST_MPEG_DASH ? "MEPG DASH" :
									mtype ==  MSYNC_MANIFEST_HLS ? "HLS" : "unknown",
							uri_size,
							oinfo_h->media_sequence,
							oinfo_h->uri);
				
				np->obj->size = ntohl(oinfo_h->size);           
				np->obj->packets = ntohl(oinfo_h->packets);            
				np->obj->crc = ntohl(oinfo_h->crc);                  
				np->obj->otype= oinfo_h->otype;              
				np->obj->mtype = mtype;
				np->obj->uri_size = uri_size;     
				np->obj->media_sequence = oinfo_h->media_sequence; 	   
				memcpy(np->obj->uri, oinfo_h->uri, MIN(uri_size, MSYNC_URI_LENGTH_MAX - 1));
				if (np->obj->fptr == NULL) {
					create_file_path_dirs(np->obj->uri);
					np->obj->fptr = fopen(np->obj->uri,"wb");
					np->obj->received_object_info_before_data = true;
				}
			}
			
			/* Object Data Packet Header */
			else if (msync_h->type == MSYNC_TYPE_ODATA && len >= MSYNC_ODATA_HEADER_LEN)
			{
				if (verbose)
					printf("  %d Data\t: offset: %u\n", 
							*sd, 
							ntohl(odata_h->offset));
				if (np->obj->fptr == NULL) {
					char buffer[32]; // The filename buffer.
    				snprintf(buffer, sizeof(char) * 32, "oid%i.tmp", ntohs(msync_h->object_id));
					np->obj->fptr = fopen(buffer,"wb");
					np->obj->received_object_info_before_data = false;
				}
				if (np->obj->fptr != NULL && lookup_packet(ntohl(odata_h->offset),np->obj->hashtab)== NULL){
					fseek(np->obj->fptr, ntohl(odata_h->offset), SEEK_SET);
					uint16_t data_len = len - MSYNC_ODATA_HEADER_LEN;
					if (rtp) 
						data_len = data_len - RTP_HEADER_LEN;
					fwrite((char *) odata_h + MSYNC_ODATA_HEADER_LEN,1,data_len,np->obj->fptr);
					put_packet(ntohl(odata_h->offset),np->obj->hashtab);
					np->obj->recvd_uniq_packets += 1;
					if (np->obj->recvd_uniq_packets == np->obj->packets) { // We received all data for this object
						fclose(np->obj->fptr);
						if (np->obj->received_object_info_before_data) {
							char buffer[32]; // The filename buffer.
    						snprintf(buffer, sizeof(char) * 32, "oid%i.tmp", ntohs(msync_h->object_id));
							create_file_path_dirs(np->obj->uri);
							rename(buffer, np->obj->uri);
						}
					}
				}

			}
			/* Object HTTP Header Packet Header */
			else if (msync_h->type == MSYNC_TYPE_OHTTP && len >= MSYNC_OHTTP_HEADER_LEN)
			{	
				if (verbose)
					printf("  %d HTTP\t: header size %u, header offset: %u\n", 
							*sd, 
							ntohl(ohttp_h->header_size),
							ntohl(ohttp_h->header_offset));
			}
			/* Object Data-part Packet Header */
			else if (msync_h->type == MSYNC_TYPE_ODATA_PART && len >= MSYNC_ODATA_PART_HEADER_LEN)
			{
				if (verbose)
					printf("  %d Object Data Part\t: offest %u, super offset: %u\n", 
							*sd, 
							ntohl(odata_part_h->offset),
							ntohl(odata_part_h->super_offset));
			}						
		}
		
	}

	pthread_cleanup_pop(1);
	return NULL;
}


/*
 * main()
 */
int main(int argc, char** argv)
{
	uint32_t layers = MSYNC_DEFAULT_LAYERS;
	struct in_addr ip_addr = { .s_addr = 0 };
	in_port_t port = htons(MSYNC_DEFAULT_PORT);
	char iname[IF_NAMESIZE] = "";

	int sockets[MSYNC_MAX_LAYERS] = { [ 0 ... MSYNC_MAX_LAYERS - 1 ] = -1 };
	pthread_t tids[MSYNC_MAX_LAYERS];
	uint32_t ii;
	int err;
	int rv = 0;

	sigset_t sigmask;
	int sig;

#ifndef TARGETOS_eCos

	const char opts[] = "m:i:l:p:rvh";
	int c;

	while ((c = getopt(argc, argv, opts)) != -1)
	{
		switch (c)
		{
		case 'm':
			if (inet_pton(AF_INET, optarg, &ip_addr) != 1)
			{
				fprintf(stderr, "Error: invalid IP address\n");
				return -1;
			}
			break;
		case 'i':
			{
				uint32_t iface = 0;
				if ((iface = if_nametoindex(optarg)) == 0)
				{
					fprintf(stderr, "Error: invalid interface name\n");
					return -1;
				}
				memset(iname, 0, IF_NAMESIZE);
				strncpy(iname, optarg, IF_NAMESIZE - 1);
			}
			break;
		case 'p':
			{
				char *endptr;
				unsigned long val = strtoul(optarg, &endptr, 10);
				if (val > UINT16_MAX || endptr == optarg || *endptr != '\0')
				{
					fprintf(stderr, "Error: invalid port (must be 0 <= port <= %u)\n", UINT16_MAX);
					return -1;
				}
				port = htons((in_port_t) val);
			}
			break;
		case 'l':
			{
				char *endptr;
				unsigned long val = strtoul(optarg, &endptr, 10);
				if (val < 1 || val > MSYNC_MAX_LAYERS || endptr == optarg || *endptr != '\0')
				{
					fprintf(stderr, "Error: invalid number of layers (must be 1 <= layers <= %u)\n", MSYNC_MAX_LAYERS);
					return -1;
				}
				layers = (uint32_t) val;
			}
			break;
		case 'r':
			rtp = true;
			break;			
		case 'v':
			verbose = 1;
			break;
		case 'h':
			usage();
			return 0;
		default:
			usage();
			return -1;
		}
	}
#else /* TARGETOS_eCos */
#define HOME_MEDIUM "238.38.43.1"
#define FLUX3_3     "238.38.100.3"
	if (inet_pton(AF_INET, HOME_MEDIUM, (void*)&ip_addr) != 1)
	{
		printf("Error: invalid IP address\n");
		return -1;
	}
	memset(iname, 0, IF_NAMESIZE);
	strncpy(iname, "bcm2", strlen("bcm2"));
	// port is initialized at default value
	// layers is initialized at default value

	// Wait to be sure IP resources are initialized
	sleep(70);
	printf("Broadpeak msync receiver test tool \n");
#endif

	if (ip_addr.s_addr == 0)
	{
		fprintf(stderr, "Error: expected IP address\n");
		return -1;
	}

	for (ii = 0; ii < layers; ++ii)
	{
		in_addr_t ip = ntohl(ip_addr.s_addr) + ii;

		if ((sockets[ii] = open_socket(iname, htonl(ip), port)) < 0)
		{
			return -1;
		}

		if ((err = pthread_create(&tids[ii], NULL, msync_receiver, (void*) &sockets[ii])) != 0)
		{
			printf("Error spawning new thread: %s", strerror(err));
			return -1;
		}
	}

	sigfillset(&sigmask);
	sigprocmask(SIG_SETMASK, &sigmask, NULL);
	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGINT);
	sigwait(&sigmask, &sig);
	fprintf(stderr, "^C caught, exiting...\n");

	for (ii = 0; ii < layers; ++ii)
	{
		in_addr_t ip = ntohl(ip_addr.s_addr) + ii;

		if ((err = pthread_cancel(tids[ii])) != 0)
		{
			fprintf(stderr, "Error cancelling thread #%d: %s", ii, strerror(err));
			rv = -1;
		}
		else if ((err = pthread_join(tids[ii], NULL)) != 0)
		{
			fprintf(stderr, "Error joinging thread #%d: %s", ii, strerror(err));
			rv = -1;
		}
		if (close_socket(sockets[ii], iname, htonl(ip)))
		{
			rv = -1;
		}
	}

	return rv;
}
