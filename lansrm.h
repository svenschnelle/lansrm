#ifndef LANSRM_H
#define LANSRM_H

#define __packed __attribute__((packed));

#include <glib.h>
#include <netinet/in.h>
#include "srm.h"

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

#define LIF_BLOCK_SIZE 256

typedef enum {
	SRM_REQUEST_CONNECT = 1,
	SRM_REQUEST_XFER = 2,
	SRM_REPLY_CONNECT = 129,
	SRM_REPLY_XFER = 130
} lansrm_request_t;

struct srm_connect_request {
	uint16_t rec_type;
	uint16_t ret_code;
	uint16_t option_code;
	uint16_t host_node;
	uint16_t version;
	uint8_t station[6];
} __packed;

struct srm_connect_reply {
	uint16_t rec_type;
	uint16_t ret_code;
	uint32_t host_ip;
	uint32_t my_ip;
	uint16_t option_code;
	uint16_t host_node;
	uint16_t version;
	uint16_t my_node;
	uint8_t my_station[6];
	uint8_t host_flag;
} __packed;

struct srm_transfer {
	uint16_t rec_type;
	uint16_t ret_code;
	uint16_t session_id;
	uint16_t version;
	uint16_t host_node;
	uint8_t unum;
	uint8_t sequence_no;
} __packed;

struct client_config {
	struct sockaddr_in addr;
	GList *volumes;
	gchar **bootfiles;
	char *bootpath;
	int bootfilefd;
	int node;
};

struct srm_client {
	struct client_config *config;
	struct sockaddr_in addr;
	GTree *files;
	char *ipstr;
	int debug_level;
	int cleanup;
	int fd;

};

struct open_file_entry {
	struct srm_volume *volume;
	GString *filename;
	off_t hdr_offset;
	int client_fd;
	int fd;
	int cwd;

};

struct lansrm_response_packet {
	struct srm_transfer xfer;
	struct srm_response_packet srm;
} __packed;

struct lansrm_request_packet {
	struct srm_transfer xfer;
	struct srm_request_packet srm;
} __packed;

#endif
