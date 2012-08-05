/*
   Copyright (C) 2012 Red Hat, Inc.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _H_MIGRATION_PROTOCOL
#define _H_MIGRATION_PROTOCOL

#include <spice/vd_agent.h>

/* ************************************************
 * src-server to dst-server migration data messages
 * ************************************************/

/* increase the version when the version of any
 * of the migration data messages is increased */
#define SPICE_MIGRATION_PROTOCOL_VERSION ~0

typedef struct __attribute__ ((__packed__)) SpiceMigrateDataHeader {
    uint32_t magic;
    uint32_t version;
} SpiceMigrateDataHeader;

/* ********************
 * Char device base
 * *******************/

/* increase the version of descendent char devices when this
 * version is increased */
#define SPICE_MIGRATE_DATA_CHAR_DEVICE_VERSION 1

/* Should be the first field of any of the char_devices migration data (see write_data_ptr) */
typedef struct __attribute__ ((__packed__)) SpiceMigrateDataCharDevice {
    uint32_t version;
    uint8_t connected;
    uint32_t num_client_tokens;
    uint32_t num_send_tokens;
    uint32_t write_size; /* write to dev */
    uint32_t write_num_client_tokens; /* how many messages from the client are part of the write_data */
    uint32_t write_data_ptr; /* offset from
                                SpiceMigrateDataCharDevice - sizeof(SpiceMigrateDataHeader) */
} SpiceMigrateDataCharDevice;

/* ********
 * spicevmc
 * ********/

#define SPICE_MIGRATE_DATA_SPICEVMC_VERSION 1 /* NOTE: increase version when CHAR_DEVICE_VERSION
                                                 is increased */
#define SPICE_MIGRATE_DATA_SPICEVMC_MAGIC (*(uint32_t *)"SVMD")
typedef struct __attribute__ ((__packed__)) SpiceMigrateDataSpiceVmc {
    SpiceMigrateDataCharDevice base;
} SpiceMigrateDataSpiceVmc;

/* *********
 * smartcard
 * *********/

#define SPICE_MIGRATE_DATA_SMARTCARD_VERSION 1 /* NOTE: increase version when CHAR_DEVICE_VERSION
                                                  is increased */
#define SPICE_MIGRATE_DATA_SMARTCARD_MAGIC (*(uint32_t *)"SCMD")
typedef struct __attribute__ ((__packed__)) SpiceMigrateDataSmartcard {
    SpiceMigrateDataCharDevice base;
    uint8_t reader_added;
    uint32_t read_size; /* partial data read from dev */
    uint32_t read_data_ptr;
} SpiceMigrateDataSmartcard;

/* *********************************
 * main channel (mainly guest agent)
 * *********************************/
#define SPICE_MIGRATE_DATA_MAIN_VERSION 1 /* NOTE: increase version when CHAR_DEVICE_VERSION
                                             is increased */
#define SPICE_MIGRATE_DATA_MAIN_MAGIC (*(uint32_t *)"MNMD")

typedef struct __attribute__ ((__packed__)) SpiceMigrateDataMain {
    SpiceMigrateDataCharDevice agent_base;
    uint8_t client_agent_started; /* for discarding messages */

    struct __attribute__ ((__packed__)) {
        /* partial data read from device. Such data is stored only
         * if the chunk header or the entire msg header haven't yet been read completely.
         * Once the headers are read, partial reads of chunks can be sent as
         * smaller chunks to the client, without the roundtrip overhead of migration data */
        uint32_t chunk_header_size;
        VDIChunkHeader chunk_header;
        uint8_t msg_header_done;
        uint32_t msg_header_partial_len;
        uint32_t msg_header_ptr;
        uint32_t msg_remaining;
        uint8_t msg_filter_result;
    } agent2client;

    struct __attribute__ ((__packed__)) {
        uint32_t msg_remaining;
        uint8_t msg_filter_result;
    } client2agent;
} SpiceMigrateDataMain;

static inline int migration_protocol_validate_header(SpiceMigrateDataHeader *header,
                                                     uint32_t magic,
                                                     uint32_t version)
{
    if (header->magic != magic) {
        spice_error("bad magic %u (!= %u)", header->magic, magic);
        return FALSE;
    }
    if (header->version > version) {
        spice_error("unsupported version %u (> %u)", header->version, version);
        return FALSE;
    }
    return TRUE;
}

#endif