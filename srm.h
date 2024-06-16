#ifndef SRM_H
#define SRM_H

#include <stdint.h>

typedef enum srm_errno {
	SRM_ERRNO_SOFTWARE_BUG = 31000,
	SRM_ERRNO_BAD_SELECT_CODE = 31001,
	SRM_ERRNO_UNALLOCATED_EXTENT = 31002,
	SRM_ERRNO_DS_ROM_MISSING = 31003,
	SRM_ERRNO_UNSUPPORTED_DAM = 31004,
	SRM_ERRNO_DEVICE_DRIVERS_DONT_MATCH = 31005,
	SRM_ERRNO_INVALID_IOS_REQUEST = 31006,
	SRM_ERRNO_ATTACH_TABLE_FULL = 31007,
	SRM_ERRNO_IMPROPER_MASS_STORAGE_DEVICE = 31008,
	SRM_ERRNO_DIRECTORY_FORMATS_DONT_MATCH = 31009,
	SRM_ERRNO_INVALID_FILE_SIZE = 31010,
	SRM_ERRNO_INVALID_FILE_ID = 31011,
	SRM_ERRNO_VOLUME_RECOVERABLE_ERROR = 31012,
	SRM_ERRNO_VOLUME_IO_ERROR = 31013,
	SRM_ERRNO_FILE_PATHNAME_MISSING = 31014,
	SRM_ERRNO_ILLEGAL_BYTE_NUMBER = 31015,
	SRM_ERRNO_CORRUPT_DIRECTORY = 31016,
	SRM_ERRNO_SUCCESSFUL_COMPLETION = 31017,
	SRM_ERRNO_SYSTEM_DOWN = 31018,
	SRM_ERRNO_FILE_UNOPENED = 31019,
	SRM_ERRNO_VOLUME_OFFLINE = 31020,
	SRM_ERRNO_VOLUME_LABELS_DONT_MATCH = 31021,
	SRM_ERRNO_PASSWORD_NOT_ALLOWED = 31022,
	SRM_ERRNO_ACCESS_TO_FILE_NOT_ALLOWED = 31023,
	SRM_ERRNO_UNSUPPORTED_DIRECTORY_OPERATION = 31024,
	SRM_ERRNO_CONFLICTING_SHARE_MODES = 31025,
	SRM_ERRNO_BAD_FILE_NAME = 31026,
	SRM_ERRNO_FILE_IN_USE = 31027,
	SRM_ERRNO_INSUFFICIENT_DISK_SPACE = 31028,
	SRM_ERRNO_DUPLICATE_FILENAMES = 31029,
	SRM_ERRNO_PHYS_EOF_ENCOUNTERED = 31030,
	SRM_ERRNO_NO_CAPABILITY_FOR_FILE = 31031,
	SRM_ERRNO_FILE_NOT_FOUND = 31032,
	SRM_ERRNO_VOLUME_IN_USE = 31033,
	SRM_ERRNO_FILE_NOT_DIRECTORY = 31034,
	SRM_ERRNO_DIRECTORY_NOT_EMPTY = 31035,
	SRM_ERRNO_VOLUME_NOT_FOUND = 31036,
	SRM_ERRNO_INVALID_PROTECT_CODE = 31037,
	SRM_ERRNO_VOLUME_UNRECOVERABLE_ERROR = 31038,
	SRM_ERRNO_PASSWORD_NOT_FOUND = 31039,
	SRM_ERRNO_DUPLICATE_PASSWORDS = 31040,
	SRM_ERRNO_DEADLOCK_DETECTED = 31041,
	SRM_ERRNO_LINK_TO_DIRECTORY_NOT_ALLOWED = 31042,
	SRM_ERRNO_RENAME_ACROSS_VOLUMES = 31043,
	SRM_ERRNO_VOLUME_DOWN = 31044,
	SRM_ERRNO_EOF_ENCOUNTERED = 31045,
	SRM_ERRNO_INVALID_FILE_CODE = 31046,
	SRM_ERRNO_FILE_LOCKED_PLEASE_RETRY = 31047,
	SRM_ERRNO_NO_REPLY = 31048,
	SRM_ERRNO_PURGE_ON_OPEN = 31049,
	SRM_ERRNO_ERROR_TOP = 31049,
} srm_errno_t;

typedef enum srm_request {
	SRM_REQ_WRITE = 1,
	SRM_REQ_POSITION = 2,
	SRM_REQ_READ = 3,
	SRM_REQ_SET_EOF = 4,
	SRM_REQ_FILEINFO = 10,
	SRM_REQ_CLOSE = 13,
	SRM_REQ_OPEN = 14,
	SRM_PURGE_LINK = 15,
	SRM_REQ_CATALOG = 16,
	SRM_REQ_CREATEFILE = 17,
	SRM_REQ_CREATELINK = 18,
	SRM_REQ_CHANGE_PROTECT = 19,
	SRM_REQ_VOLSTATUS = 22,
	SRM_REQ_XCHG_OPEN = 29,
	SRM_REQ_RESET = 1000,
	SRM_REQ_AREYOUALIVE = 1001
} srm_request_t;

#define SRM_VOLNAME_LENGTH	16

struct srm_send_header {
	uint8_t srcaddr;		/* 0 */
	uint8_t len_lo;			/* 1 */
	uint8_t len_hi;			/* 2 */
	uint8_t level;			/* 3 */
	uint32_t message_length;	/* 0x04 */
	uint32_t request_type;		/* 0x08 */
	uint32_t user_sequencing_field;	/* 0xc */
} __packed;

struct srm_return_header {
	uint8_t srcaddr;		/* 0 */
	uint8_t len_lo;			/* 1 */
	uint8_t len_hi;			/* 2 */
	uint8_t level;			/* 3 */
	uint32_t message_length;	/* 4 */
	uint32_t return_request_type;	/* 8 */
	uint32_t user_sequencing_field;	/* 12 */
	uint32_t status;		/* 16 */
} __packed;

struct srm_date_type {
	uint16_t id;
	uint16_t date;
	uint32_t seconds_since_midnight;
} __packed;

struct srm_file_info {
	char filename[16];			/* 0 */
	uint32_t open_flag;			/* 16 */
	uint32_t share_code;			/* 20 */
	uint32_t file_code;			/* 24 */
	uint32_t record_mode;			/* 28 */
	uint32_t max_record_size;		/* 32 */
	uint32_t max_file_size;			/* 36 */
	struct srm_date_type creation_date;	/* 40 */
	struct srm_date_type last_access;	/* 45 */
	uint16_t capabilities;			/* 50 */
	uint16_t perm;				/* 52 */
	uint32_t logical_eof;			/* 54 */
	uint32_t physical_size;			/* 58 */
} __packed;

struct srm_address {
	uint32_t address1;
	uint32_t haddress;
	uint32_t unit_num;
	uint32_t volume_num;
} __packed;

struct srm_file_header {
	uint32_t file_name_sets;
	uint32_t working_directory;
	uint16_t __pad0;
	uint16_t path_type;
	char root_password[16];
} __packed;

struct srm_file_name_set {
	char file_name[16];
	char password[16];
	uint32_t __pad0;
} __packed;

struct srm_volume_header {
	uint32_t __pad0;
	char driver_name[16];
	char catalogue_organization[16];
	uint32_t device_address_present;
	struct srm_address device_address;
	char volume_name[SRM_VOLNAME_LENGTH];
} __attribute__((packed));

struct srm_volume_status {
	struct srm_send_header hdr;
	struct srm_volume_header vh;
} __packed;

struct srm_volume_info {
	uint32_t free_blocks;
	uint32_t bad_blocks;
	uint32_t media_origin;
	uint32_t interleave;
	char volume_label[SRM_VOLNAME_LENGTH];
} __packed;

struct srm_catalog {
	struct srm_send_header hdr;
	uint32_t max_num_files;
	uint32_t file_index;
	uint32_t __pad0;
	struct srm_volume_header vh;
	struct srm_file_header fh;
	uint32_t __pad1;
	struct srm_file_name_set filenames[0];
} __packed;

struct srm_file_open {
	struct srm_send_header hdr;
	struct srm_volume_header vh;
	struct srm_file_header fh;
	uint32_t __pad0;
	uint32_t __pad1;
	uint32_t share_code;
	uint32_t __pad2;
	uint16_t __pad3;
	uint16_t open_type;
	struct srm_file_name_set filenames[0];
} __packed;

struct srm_write {
	struct srm_send_header hdr;
	uint32_t implicit_unlock;
	uint32_t file_id;
	uint32_t access_code;
	uint32_t __pad[2];
	uint32_t requested;
	uint32_t offset;
	uint32_t __pad1;
	uint32_t flush_buffer;
	uint8_t data[0];
} __packed;

struct srm_create_file {
	struct srm_send_header hdr;
	struct srm_volume_header vh;
	struct srm_file_header fh;
	uint32_t file_code;
	uint32_t record_mode;
	uint32_t max_record_size;
	uint32_t first_extent;
	uint32_t contiguous_first_extent;
	uint32_t secondary_extent;
	uint32_t max_file_size;
	uint32_t boot_start_address;
	uint32_t num_protect_code_sets;
	uint32_t label_included_flag;
	struct srm_file_name_set filenames[0];
} __packed;

struct srm_create_link {
	struct srm_send_header hdr;
	struct srm_volume_header vh;
	struct srm_file_header fh_old;
	struct srm_file_header fh_new;
	uint32_t purge_old_link;
	struct srm_file_name_set filenames[0];
} __packed;

struct srm_purge_link {
	struct srm_send_header hdr;
	struct srm_volume_header vh;
	struct srm_file_header fh;
	struct srm_file_name_set filenames[0];
} __packed;

struct srm_read {
	struct srm_send_header hdr;
	uint32_t implicit_unlock;
	uint32_t file_id;
	uint32_t access_code;
	uint32_t __pad0;
	uint32_t __pad1;
	uint32_t requested;
	uint32_t offset;
} __packed;

struct srm_fileinfo {
	struct srm_send_header hdr;
	uint32_t implicit_unlock;
	uint32_t file_id;
} __packed;

struct srm_xchg_open {
	struct srm_send_header hdr;
	uint32_t file_id1;
	uint32_t file_id2;
} __packed;

struct srm_close {
	struct srm_send_header hdr;
	uint32_t file_id;
	char directory_password[16];
	char file_password[16];
	uint32_t __pad;
	uint32_t nodeallocate;
} __packed;

struct srm_position {
	struct srm_send_header hdr;
	uint32_t implicit_unlock;
	uint32_t file_id;
	uint16_t __pad0;
	uint16_t position_type; // XXX: check
	uint32_t offset;
} __packed;

struct srm_return_volume_status {
	struct srm_return_header hdr;
	uint16_t __pad0;
	uint8_t srmux;
	uint8_t exist;
	uint32_t interleave;
	char volname[SRM_VOLNAME_LENGTH];
} __packed;

struct srm_return_file_open {
	struct srm_return_header hdr;
	uint32_t file_id;
	uint32_t record_mode;
	uint32_t max_record_size;
	uint32_t max_file_size;
	uint32_t file_code;
	uint32_t open_logical_eof;
	uint32_t share_bits;
	uint32_t sec_ext_size;
	uint32_t boot_start_address;
} __packed;

struct srm_return_catalog {
	struct srm_return_header hdr;		/* 0 */
	uint32_t __pad0;			/* 20 */
	uint32_t num_files;			/* 24 */
	struct srm_file_info fi[8];
} __packed;

struct srm_return_read {
	struct srm_return_header hdr;		/* 0 */
	uint32_t actual;			/* 20 */
	uint32_t __pad[4];			/* 24 */
	uint8_t data[512];			/* 40 */
} __packed;

struct srm_return_write {
	struct srm_return_header hdr;		/* 0 */
	uint32_t actual;			/* 20 */
} __packed;

struct srm_return_empty {
	struct srm_return_header hdr;		/* 0 */
} __packed;

struct srm_return_fileinfo {
	struct srm_return_header hdr;		/* 0 */
	uint32_t current_record;
	struct srm_file_info fi;
} __packed;

struct lif_header {
	char name[10];
	uint16_t type;
	uint32_t loc;
	uint32_t size;
	uint16_t tim0;
	uint16_t tim1;
	uint16_t tim2;
	uint16_t volnr;
	uint32_t gp;
} __packed;

#endif /* SRM_H */
