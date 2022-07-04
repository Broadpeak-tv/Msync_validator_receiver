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

# include <stdint.h>

#define MSYNC_URI_LENGTH_MAX       			4096
#define MSYNC_VERSION                       0x03
#define MSYNC_PAYLOAD_MTU_MAX               1472   /*!< Ethernet MTU minus IP and UDP headers */

/* packet types */
#define MSYNC_PACKET_TYPE_OINFO             0x01   /*!< MSync object information packet */
#define MSYNC_PACKET_TYPE_OINFO_REDUNDANCY  0x02   /*!< MSync object information redundancy packet */
#define MSYNC_PACKET_TYPE_ODATA             0x03   /*!< MSync object data packet */
#define MSYNC_PACKET_TYPE_RESERVED          0x04   /*!< MSync reserved type */
#define MSYNC_PACKET_TYPE_OHTTP_HEADER      0x05   /*!< MSync object http header packet */
#define MSYNC_PACKET_TYPE_ODATA_PART        0x06   /*!< MSync object data part packet */

/* object types */
#define MSYNC_OBJECT_TYPE_UNKNOWN           0x00   /*!< Reserved */
#define MSYNC_OBJECT_TYPE_MEDIA_MANIFEST    0x01   /*!< media manifest (playlist) */
#define MSYNC_OBJECT_TYPE_RESERVED          0x02   /*!< Reserved */
#define MSYNC_OBJECT_TYPE_MEDIA_MPEG2TS     0x03   /*!< media data or data-part: Transport stream (MPEG2-TS) */
#define MSYNC_OBJECT_TYPE_MEDIA_CMAF        0x04   /*!< media data or data-part: MPEG4 (CMAF) */
#define MSYNC_OBJECT_TYPE_CONTROL           0x05   /*!< control: control plane information (e.g. multicast gateway configuration) */

/* manifest types */
#define MSYNC_MANIFEST_TYPE_NA              0x00   /*!< Not Applicable */
#define MSYNC_MANIFEST_TYPE_MPEG_DASH       0x01   /*!< MPEG Dash */
#define MSYNC_MANIFEST_TYPE_HLS             0x02   /*!< HLS */

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

/*!
 * Object Info Packet Header definition
 *
 * Contain info on object when the MSync header type is MSYNC_PACKET_TYPE_OINFO
 */
typedef struct
{
  msync_header_t h;               /*!< MSync header */
  uint32_t objSize;               /*!< Object size in bytes */
  uint32_t msyncPacketCount;      /*!< Number of MSync packets the object is broken up into */
  uint32_t objCrc;                /*!< object CRC */
  uint8_t  objType;               /*!< object type (one of MSYNC_OBJECT_TYPE_* ) */
  uint8_t  reserved;              /*!< Reserved*/
  uint16_t mtype_UriSize;         /*!< Manifest type (4 first bits) (one of MSYNC_MANIFEST_* ) and size of the URI (12 next bits)*/
  uint32_t mediaSequence;       /*!< Media sequence number*/
  char uri[MSYNC_URI_LENGTH_MAX]; /*!< Object URI */
} msync_oinfo_header_t;

/*!
 * Object Data Packet Header definition
 *
 * Contain info of object data, when the MSync header type is MSYNC_PACKET_TYPE_ODATA
 * This header is immediately followed by the data itself
 */
typedef struct msync_odata_header
{
  msync_header_t h;               /*!< MSync header */
  uint32_t objOffset;             /*!< Object offset of data */
} msync_odata_header_t;

#define MSYNC_ODATA_HEADER_LEN  8

/*!
 * Object HTTP Header Packet Header definition
 *
 * Contain info of object HTTP header, when the MSync header type is MSYNC_PACKET_TYPE_OHTTP_HEADER
 * This header is immediately followed by the http header itself
 */
typedef struct msync_ohttp_header
{
  msync_header_t h;               /*!< MSync header */
  uint16_t headerSize;            /*!< Total size of the HTTP header in bytes */
  uint16_t headerOffset;          /*!< HTTP header offset of data */
} msync_ohttp_header_t;

#define MSYNC_OHTTP_HEADER_LEN  8

/*!
 * Object Data-part Packet Header definition
 *
 * Contain info of object data-part, when the MSync header type is MSYNC_PACKET_TYPE_ODATA_PART
 * This header is immediately followed by the data part itself
 */
typedef struct msync_odata_part_header
{
  msync_header_t h;               /*!< MSync header */
  uint32_t objOffset;             /*!< Object offset of data */
  uint32_t superObjOffset;        /*!< Super object offset of data */
} msync_odata_part_header_t;

#define MSYNC_ODATA_PART_HEADER_LEN  12


#endif /* MSYNC_PROTOCOL_H */