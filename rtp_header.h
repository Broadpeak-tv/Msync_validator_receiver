/*!
 * Msync Validator Receiver
 * https://github.com/Broadpeak-tv/Msync_validator_receiver.git
 * Copyright © 2022 Broadpeak, S.A. 
 * All Rights Reserved.
 * 
 * This code is licensed under the Apache License, Version 2.0 (the "License").
 */

#ifndef RTP_HEADER_H
#define RTP_HEADER_H

#ifndef TARGETOS_eCos
#include <stdint.h>
#include <endian.h>
#else
#include <sys/types.h>
#endif


typedef struct rtp_hdr
{
#if __BYTE_ORDER == __BIG_ENDIAN
	uint16_t v: 2;       /* packet type/version    */
	uint16_t p: 1;       /* padding flag           */
	uint16_t x: 1;       /* extension flag         */
	uint16_t cc: 4;      /* CSRC count             */
	uint16_t m: 1;       /* marker bit             */
	uint16_t pt: 7;      /* payload type           */
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t cc: 4;      /* CSRC count             */
	uint16_t x: 1;       /* header extension flag  */
	uint16_t p: 1;       /* padding flag           */
	uint16_t v: 2;       /* packet type/version    */
	uint16_t pt: 7;      /* payload type           */
	uint16_t m: 1;       /* marker bit             */
#else
# error "Unsupported endianess"
#endif
	uint16_t seq;        /* sequence number        */
	uint32_t ts;         /* timestamp              */
	uint32_t ssrc;       /* synchronization source */
} rtp_hdr_t;


#define RTP_HEADER_LEN 12
#if 4 < __GNUC__ || (__GNUC__ == 4 && 6 <= __GNUC_MINOR__) && !defined __cplusplus
_Static_assert(sizeof(rtp_hdr_t) == RTP_HEADER_LEN, "Wrong RTP header packing");
#endif


#endif   /* RTP_HEADER_H */
