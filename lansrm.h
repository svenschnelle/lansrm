#ifndef LANSRM_H
#define LANSRM_H

#include <glib.h>
#include <netinet/in.h>

#define __packed __attribute__((packed));

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

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
	uint8_t data[0];
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
	struct srm_request_xfer xfer;
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
};

struct open_file_entry {
	GString *filename;
	off_t hdr_offset;
	int client_fd;
	int fd;
	int cwd;
};

void srm_handle_request(struct srm_client *client, void *buf, size_t len);
void lansrm_send(struct srm_client *client, void *buf, size_t len);
void srm_debug(int level, struct srm_client *client, char *fmt, ...);

#endif
