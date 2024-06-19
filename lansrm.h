#ifndef LANSRM_H
#define LANSRM_H

#define __packed __attribute__((packed));

#include <glib.h>
#include <netinet/in.h>
#include "srm.h"

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))
#define LIF_BLOCK_SIZE 256

typedef enum {
	SRM_DEBUG_REQUEST=1,
	SRM_DEBUG_RESPONSE=2,
	SRM_DEBUG_CONNECT=4,
	SRM_DEBUG_XFER=8,
	SRM_DEBUG_FILE=16,
	SRM_DEBUG_PACKET_RX=32,
	SRM_DEBUG_PACKET_TX=64,
	SRM_DEBUG_ERROR=128
} srm_debug_level_t;

typedef enum {
	SRM_REQUEST_CONNECT = 1,
	SRM_REQUEST_XFER = 2,
	SRM_REPLY_CONNECT = 129,
	SRM_REPLY_XFER = 130
} lansrm_request_t;

struct srm_request_connect {
	uint16_t rec_type;
	uint16_t ret_code;
	uint16_t option_code;
	uint16_t host_node;
	uint16_t version;
	uint8_t station[6];
} __packed;

struct srm_reply {
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

struct srm_request_xfer {
	uint16_t rec_type;
	uint16_t ret_code;
	uint16_t session_id;
	uint16_t version;
	uint16_t host_node;
	uint8_t unum;
	uint8_t sequence_no;
} __packed;

struct config {
	GKeyFile *keyfile;
	char *interface;
	char *chroot;
	char *root;
	int foreground;
	int debug;
};
extern struct config config;

struct srm_client {
	struct sockaddr_in addr;
	GList *volumes;
	GTree *files;
	int debug_level;
	char *hostname;
	int fd;
};

struct srm_volume {
	char *name;
	char *path;
	int index;
	DIR *dir;
	int dirfd;
	gid_t gid;
	uid_t uid;
	mode_t umask;
	mode_t old_umask;
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
	struct srm_request_xfer xfer;
	struct srm_response_packet srm;
} __packed;

struct lansrm_request_packet {
	struct srm_request_xfer xfer;
	struct srm_request_packet srm;
} __packed;

void srm_debug(int level, struct srm_client *client, char *fmt, ...) __attribute__ ((format (printf, 3, 4)));

#endif
