/*!
 * Msync Validator Receiver
 * https://github.com/Broadpeak-tv/Msync_validator_receiver.git
 * Copyright © 2022 Broadpeak, S.A. 
 * All Rights Reserved.
 * 
 * This code is licensed under the Apache License, Version 2.0 (the "License").
 */

#ifndef MSYNC_PROTOCOL_H
#define MSYNC_PROTOCOL_H


#if defined linux || defined __linux
# include <stdint.h>
#elif defined TARGETOS_eCos
# include <sys/types.h>
#else
# ifndef uint32_t
#  define uint32_t    unsigned __int32
# endif
# ifndef uint16_t
#  define uint16_t    unsigned __int16
# endif
# ifndef uint8_t
#  define uint8_t    unsigned __int8
# endif
#endif

#ifdef TARGETOS_eCos
#define inet_pton(a, s, d) inet_pton(a, (char*) (s), d)
#endif

#define MSYNC_URI_LENGTH_MAX       300
#define MSYNC_VERSION              0x03
#define MSYNC_PAYLOAD_MTU_MAX      1472   /*!< Ethernet MTU minus IP and UDP headers */

/* packet types */
#define MSYNC_TYPE_OINFO           0x01   /*!< MSync object information packet */
#define MSYNC_TYPE_OINFO_CHECK     0x02   /*!< MSync object information redundancy packet */
#define MSYNC_TYPE_ODATA           0x03   /*!< MSync object data packet */
#define MSYNC_TYPE_RESERVED        0x04   /*!< MSync reserved type */
#define MSYNC_TYPE_OHTTP           0x05   /*!< MSync object http header packet */
#define MSYNC_TYPE_ODATA_PART      0x06   /*!< MSync object data part packet */

/* object types */
#define MSYNC_OBJECT_TYPE_UNKNOWN    	0x00   /*!< Reserved */
#define MSYNC_OBJECT_TYPE_MANIFEST   	0x01   /*!< media manifest (playlist) */
#define MSYNC_OBJECT_TYPE_RESERVED      0x02   /*!< Reserved */
#define MSYNC_OBJECT_TYPE_MEDIA_MPEG2TS	0x03   /*!< media data or data-part: Transport stream (MPEG2-TS) */
#define MSYNC_OBJECT_TYPE_MEDIA_CMAF 	0x04   /*!< media data or data-part: MPEG4 (CMAF) */
#define MSYNC_OBJECT_TYPE_CONTROL		0x05   /*!< control: control plane information (e.g. multicast gateway configuration) */

/* manifest types */
#define MSYNC_MANIFEST_NA    		 0x00   /*!< Not Applicable */
#define MSYNC_MANIFEST_MPEG_DASH   	 0x01   /*!< MPEG Dash */
#define MSYNC_MANIFEST_HLS		     0x02   /*!< HLS */

/*!
 * MSync Header definition
 *
 * Specify the protocol version, the kind of MSync packet, and the object identifier
 */
typedef struct
{
	uint8_t version;               /*!< MSync protocol version (MSYNC_VERSION) */
	uint8_t type;                  /*!< MSync packet type (one of MSYNC_TYPE_*) */
	uint16_t object_id;            /*!< Object identifier  (different for each transfered object) */
} msync_header_t;

#define MSYNC_HEADER_LEN  4
#if 4 < __GNUC__ || (__GNUC__ == 4 && 6 <= __GNUC_MINOR__) && !defined __cplusplus
_Static_assert(sizeof(msync_header_t) == MSYNC_HEADER_LEN, "Wrong MSync header size");
#endif


/*!
 * Object Info Packet Header definition
 *
 * Contain info on object when the MSync header type is MSYNC_TYPE_ODATA
 */
typedef struct
{
	msync_header_t h;              /*!< MSync header */
	uint32_t size;                 /*!< Object size in bytes */
	uint32_t packets;              /*!< Number of MSync packets the object is broken up into */
	uint32_t crc;                  /*!< object CRC */
	uint8_t  otype;                /*!< object type (one of MSYNC_OBJECT_TYPE_* ) */
	uint8_t  reserved;         	   /*!< Reserved*/
	uint16_t mtype_uri_size;       /*!< Manifest type (4 first bits) (one of MSYNC_MANIFEST_* ) and size of the URI (12 next bits)*/
	uint32_t media_sequence;  	   /*!< Media sequence number*/
	char uri[MSYNC_URI_LENGTH_MAX];      /*!< Object URI */
} msync_oinfo_header_t;


/*!
 * Object Data Packet Header definition
 *
 * Contain info of object data, when the MSync header type is MSYNC_TYPE_ODATA
 * This header is immediately followed by the data itself
 */
typedef struct msync_odata_header
{
	msync_header_t h;              /*!< MSync header */
	uint32_t offset;               /*!< Object offset of data */
} msync_odata_header_t;

#define MSYNC_ODATA_HEADER_LEN  8
#if 4 < __GNUC__ || (__GNUC__ == 4 && 6 <= __GNUC_MINOR__) && !defined __cplusplus
_Static_assert(sizeof(msync_odata_header_t) == MSYNC_ODATA_HEADER_LEN, "Wrong FileChunk header size");
#endif



/*!
 * Object HTTP Header Packet Header definition
 *
 * Contain info of object HTTP header, when the MSync header type is MSYNC_TYPE_OHTTP
 * This header is immediately followed by the http header itself
 */
typedef struct msync_ohttp_header
{
	msync_header_t h;              /*!< MSync header */
	uint16_t header_size;          /*!< Total size of the HTTP header in bytes */
	uint16_t header_offset;        /*!< HTTP header offset of data */
} msync_ohttp_header_t;

#define MSYNC_OHTTP_HEADER_LEN  8
#if 4 < __GNUC__ || (__GNUC__ == 4 && 6 <= __GNUC_MINOR__) && !defined __cplusplus
_Static_assert(sizeof(msync_ohttp_header_t) == MSYNC_OHTTP_HEADER_LEN, "Wrong FileChunk header size");
#endif

/*!
 * Object Data-part Packet Header definition
 *
 * Contain info of object data-part, when the MSync header type is MSYNC_TYPE_ODATA_PART
 * This header is immediately followed by the data part itself
 */
typedef struct msync_odata_part_header
{
	msync_header_t h;              /*!< MSync header */
	uint32_t offset;               /*!< Object offset of data */
	uint32_t super_offset;         /*!< Super object offset of data */
} msync_odata_part_header_t;

#define MSYNC_ODATA_PART_HEADER_LEN  12
#if 4 < __GNUC__ || (__GNUC__ == 4 && 6 <= __GNUC_MINOR__) && !defined __cplusplus
_Static_assert(sizeof(msync_odata_part_header_t) == MSYNC_ODATA_PART_HEADER_LEN, "Wrong FileChunk header size");
#endif

#endif /* MSYNC_PROTOCOL_H */
