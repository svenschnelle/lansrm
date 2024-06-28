#ifndef LANSRM_RMP_H
#define LANSRM_RMP_H

#include <stdint.h>
#include <sys/socket.h>
#include <glib.h>
#include <linux/if_packet.h>
#include <sys/epoll.h>

#define IEEE_DSAP_HP 0xf8
#define IEEE_SSAP_HP 0xf8
#define IEEE_CNTL_HP 0x300

#define HPEXT_DXSAP 0x608
#define HPEXT_SXSAP 0x609

typedef enum {
	RMP_BOOT_REQ=1,
	RMP_BOOT_REPLY=129,
	RMP_READ_REQ=2,
	RMP_READ_REPLY=130,
	RMP_BOOT_DONE=3
} rmp_reqtype_t;

typedef enum {
	RMP_E_OKAY=0,
	RMP_E_EOF=2,
	RMP_E_ABORT=3,
	RMP_E_BUSY=4,
	RMP_E_TIMEOUT=5,
	RMP_E_NOFILE=16,
	RMP_E_OPENFILE=17,
	RMP_E_NODFLT=18,
	RMP_E_OPENDFLT=19,
	RMP_E_BADSID=25,
	RMP_E_BADPACKET=27
} rmp_error_t;

#define RMP_VERSION     2
#define RMP_TIMEOUT     600
#define RMP_PROBESID    0xffff
#define RMP_HOSTLEN     13
#define RMP_MACHLEN     20

#define RMP_ALEN 6
struct rmp_header {
	uint8_t daddr[RMP_ALEN];
	uint8_t saddr[RMP_ALEN];
	uint16_t len;
} __packed;

struct rmp_packet {
	uint8_t		dsap;
	uint8_t		ssap;
	uint16_t	ctrl;
	uint8_t		pad[2];
	uint16_t	dxsap;
	uint16_t	sxsap;
} __packed;

struct rmp_packet_reply {
	uint8_t		dsap;
	uint8_t		ssap;
	uint16_t	ctrl;
	uint8_t		pad[3];
	uint16_t	dxsap;
	uint16_t	sxsap;
} __packed;

struct rmp_raw {
	uint8_t  rmp_type;
	uint8_t  rmp_rawdata[0];
};

struct rmp_boot_request {
	uint8_t		type;
	uint8_t		retcode;
	uint32_t	seqno;
	uint16_t	session;
	uint16_t	version;
	char		machtype[20];
	uint8_t		filenamesize;
	char		filename[0];
} __packed;

struct rmp_boot_reply {
	uint8_t		type;
	uint8_t		retcode;
	uint32_t	seqno;
	uint16_t	session;
	uint16_t	version;
	uint8_t		filenamesize;
	char		filename[0];
} __packed;

struct rmp_read_request {
	uint8_t		type;
	uint8_t		retcode;
	uint32_t	offset;
	uint16_t	session;
	uint16_t	size;
} __packed;

struct rmp_read_reply {
	uint8_t		type;
	uint8_t		retcode;
	uint32_t	offset;
	uint16_t	session;
	uint8_t		data[0];
//	uint8_t		unused;
} __packed;

struct fd_ctx;
struct rmp_epoll_ctx {
	struct fd_ctx *fdctx;
	GTree *clients;
	void *inbuf;
	void *outbuf;
	struct epoll_event event;
	struct sockaddr_ll addr;
	socklen_t addrlen;
	ssize_t inlen;
	ssize_t outlen;
	int fd;
};

int create_rmp_socket(char *dev);
void rmp_init(GTree *clients);
void rmp_exit(void);
#endif
