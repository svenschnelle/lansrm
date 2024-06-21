#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <glib.h>
#include <stdarg.h>
#include <endian.h>
#include "lansrm.h"
#include "srm.h"
#include "epoll.h"
#include "debug.h"
#include "config.h"

static struct sockaddr_in bcaddr;
static struct srm_epoll_ctx *srmctx;

struct srm_epoll_ctx {
	struct fd_ctx *fdctx;
	GTree *clients;
	void *inbuf;
	void *outbuf;
	struct sockaddr_in addr;
	socklen_t addrlen;
	ssize_t inlen;
	ssize_t outlen;
	int fd;
};

static int path_levels(char *pathname)
{
	int level = 0;

	gchar **parts = g_strsplit(pathname, "/", 0);
	for (int i = 0; parts[i]; i++) {
		if (!strcmp(parts[i], "."))
			continue;
		if (!strcmp(parts[i], ".."))
			level--;
		else
			level++;
	}
	g_strfreev(parts);
	return level;
}

static char *srm_to_c_string(char *s)
{
	char *p, *ret = strndup(s, SRM_VOLNAME_LENGTH);

	if ((p = strchr(ret, ' ')))
		*p = '\0';
	return ret;
}

static void c_string_to_srm(char *d, char *s)
{
	memset(d, ' ', SRM_VOLNAME_LENGTH);
	memcpy(d, s, MIN(SRM_VOLNAME_LENGTH, strlen(s)));
}

static struct srm_volume *get_volume_by_name(struct srm_client *client, char *name)
{
	for (GList *p = client->config->volumes; p; p = g_list_next(p)) {
		struct srm_volume *volume = p->data;

		if (!strcmp(volume->name, name))
			return volume;
	}
	return NULL;
}

static struct srm_volume *get_volume_by_index(struct srm_client *client, int index)
{
	if (!index)
		index = 8;

	for (GList *p = client->config->volumes; p; p = g_list_next(p)) {
		struct srm_volume *volume = p->data;

		if (volume->index == index)
			return volume;
	}
	return NULL;
}

static int srm_drop_privs(struct srm_client *client, struct srm_volume *volume)
{
	if (volume->gid && setresgid(volume->gid, volume->gid, 0) == -1) {
		srm_debug(SRM_DEBUG_ERROR, client->ipstr, "%s: setregid(%d): %m\n",
			  __func__, volume->gid);
		return -1;
	}

	if (volume->uid && setresuid(volume->uid, volume->uid, 0) == -1) {
		srm_debug(SRM_DEBUG_ERROR, client->ipstr, "%s: setreuid(%d): %m\n",
			  __func__, volume->uid);
		return -1;
	}

	volume->old_umask = umask(volume->umask);
	return 0;
}

static int srm_restore_privs(struct srm_client *client, struct srm_volume *volume)
{
	if (volume->uid && setresuid(0, 0, 0) == -1) {
		srm_debug(SRM_DEBUG_ERROR, client->ipstr, "%s: setreuid: %m\n", __func__);
		return -1;
	}

	if (volume->gid && setresgid(0, 0, 0) == -1) {
		srm_debug(SRM_DEBUG_ERROR, client->ipstr, "%s: setregid: %m\n", __func__);
		return -1;
	}
	umask(volume->old_umask);
	return 0;
}

static int srm_volume_lstat(struct srm_client *client,
			    struct srm_volume *volume,
			    const char *filename,
			    struct stat *out)
{
	int ret;

	if (srm_drop_privs(client, volume) == -1)
		return -1;
	ret = lstat(filename, out);
	if (srm_restore_privs(client, volume) == -1)
		return -1;
	return ret;
}

static int srm_volume_mkdir(struct srm_client *client,
			    struct srm_volume *volume,
			    const char *filename)
{
	int ret;

	if (srm_drop_privs(client, volume) == -1)
		return -1;
	ret = mkdir(filename, 0777);
	if (srm_restore_privs(client, volume) == -1)
		return -1;
	return ret;
}

static int srm_volume_unlink_file(struct srm_client *client,
				  struct srm_volume *volume,
				  const char *filename)
{
	int ret;

	if (srm_drop_privs(client, volume) == -1)
		return -1;
	ret = unlink(filename);
	if (srm_restore_privs(client, volume) == -1)
		return -1;
	return ret;
}

static int srm_volume_link(struct srm_client *client,
			   struct srm_volume *volume,
			   const char *from,
			   const char *to)
{
	int ret;

	if (srm_drop_privs(client, volume) == -1)
		return -1;
	ret = link(from, to);
	if (srm_restore_privs(client, volume) == -1)
		return -1;
	return ret;
}

static int srm_volume_rename(struct srm_client *client,
			     struct srm_volume *volume,
			     const char *from,
			     const char *to)
{
	int ret;

	if (srm_drop_privs(client, volume) == -1)
		return -1;
	ret = rename(from, to);
	if (srm_restore_privs(client, volume) == -1)
		return -1;
	return ret;
}

static int srm_volume_open_file(struct srm_client *client,
				struct srm_volume *volume,
				const char *filename, int flags)
{
	int fd;

	if (srm_drop_privs(client, volume) == -1)
		return -1;
	fd = open(filename, flags, 0777);
	if (srm_restore_privs(client, volume) == -1)
		return -1;
	return fd;
}

static int handle_srm_reset(struct srm_client *client)
{
	client->cleanup = 1;
	return 1;
}

static int handle_srm_areyoualive(void)
{
	return 0x01000000;
}

static int errno_to_srm_error(struct srm_client *client)
{
	switch(errno) {
	case 0:
		return 0;
	case ENOSPC:
		return SRM_ERRNO_INSUFFICIENT_DISK_SPACE;
	case EEXIST:
		return SRM_ERRNO_DUPLICATE_FILENAMES;
	case EXDEV:
		return SRM_ERRNO_RENAME_ACROSS_VOLUMES;
	case ENOENT:
		return SRM_ERRNO_FILE_NOT_FOUND;
	case EPERM:
	case EACCES:
		return SRM_ERRNO_ACCESS_TO_FILE_NOT_ALLOWED;
	case EISDIR:
	case ENOTDIR:
		return SRM_ERRNO_FILE_NOT_FOUND;
	case EIO:
		return SRM_ERRNO_VOLUME_IO_ERROR;
	case EINVAL:
		return SRM_ERRNO_VOLUME_IO_ERROR;
	default:
		srm_debug(SRM_DEBUG_ERROR, client->ipstr, "%s: unhandled errno %d (%m)\n", __func__, errno);
		return SRM_ERRNO_SOFTWARE_BUG;
	}
}

static struct open_file_entry *find_file_entry(struct srm_client *client, int fd)
{
	return g_tree_lookup(client->files, &fd);
}

static int handle_srm_write(struct srm_client *client,
			    struct srm_write *request,
			    struct srm_return_write *response,
			    int *responselen)
{
	uint32_t offset,requested, id, acc;
	struct open_file_entry *entry;
	ssize_t len = 0;

	*responselen = sizeof(struct srm_return_write);

	requested = ntohl(request->requested);
	id = ntohl(request->file_id);
	acc = ntohl(request->access_code);
	offset = ntohl(request->offset);

	entry = find_file_entry(client, id);
	if (!entry)
		return SRM_ERRNO_FILE_UNOPENED;

	if ((acc == 0 && lseek(entry->fd, offset + entry->hdr_offset, SEEK_SET) == -1))
		return errno_to_srm_error(client);

	len = write(entry->fd, request->data, requested);
	if (len == -1)
		return errno_to_srm_error(client);

	response->actual = htonl(len);
	srm_debug(SRM_DEBUG_REQUEST, client->ipstr, "%s: WRITE offset=%x, requested=%d, written=%zd acc=%d\n",
		  __func__, offset, requested, len, acc);
	return 0;
}

static int handle_srm_position(struct srm_client *client,
			       struct srm_position *request)
{
	struct open_file_entry *entry;
	uint32_t id, offset;
	uint8_t whence;

	offset = ntohl(request->offset);
	whence = request->position_type ? SEEK_CUR : SEEK_SET;
	id = ntohl(request->file_id);

	entry = find_file_entry(client, id);
	if (!entry)
		return SRM_ERRNO_FILE_UNOPENED;

	if (whence == SEEK_SET)
		offset += entry->hdr_offset;

	if (lseek(entry->fd, offset, whence) == -1)
		return errno_to_srm_error(client);

	srm_debug(SRM_DEBUG_REQUEST, client->ipstr, "%s: POSITION id=%x offset=%x, whence=%d\n",
		  __func__, entry ? entry->client_fd : 0, offset, whence);

	return 0;
}

static int handle_srm_read(struct srm_client *client,
			   struct srm_read *request,
			   struct srm_return_read *response,
			   int *responselen)
{
	uint32_t requested, offset, id, acc;
	struct open_file_entry *entry;
	ssize_t len = 0;

	requested = ntohl(request->requested);
	offset = ntohl(request->offset);
	id = ntohl(request->file_id);
	acc = ntohl(request->access_code);

	entry = find_file_entry(client, id);
	if (!entry)
		return SRM_ERRNO_FILE_UNOPENED;

	if (acc == 0 && lseek(entry->fd, offset + entry->hdr_offset, SEEK_SET) == -1)
		return errno_to_srm_error(client);

	if (requested > 512)
		requested = 512;

	len = read(entry->fd, response->data, requested);
	if (len == -1)
		return errno_to_srm_error(client);

	if (len > 0)
		response->actual = htonl(len);

	*responselen = offsetof(struct srm_return_read, data) + len;

	srm_debug(SRM_DEBUG_REQUEST, client->ipstr, "%s: READ file id=%x size=%d "
		  "actual=%zd offset=%x accesscode=%d, hdr_offset=%zx\n",
		  __func__, entry ? entry->client_fd : 0,
		  requested, len, offset, acc, entry->hdr_offset);
	return len != requested ? SRM_ERRNO_EOF_ENCOUNTERED : 0;
}

static int handle_srm_set_eof(struct srm_client *client,
			      struct srm_set_eof *request)
{
	struct open_file_entry *entry;
	uint32_t id, offset;
	uint8_t whence;
	off_t pos;

	offset = ntohl(request->offset);
	whence = request->position_type ? SEEK_CUR : SEEK_SET;
	id = ntohl(request->file_id);

	entry = find_file_entry(client, id);
	if (!entry)
		return SRM_ERRNO_FILE_UNOPENED;
	if (whence == SEEK_SET)
		offset += entry->hdr_offset;
	pos = lseek(entry->fd, offset, whence);
	if (pos == -1)
		return errno_to_srm_error(client);
	if (ftruncate(entry->fd, pos) == -1)
		return errno_to_srm_error(client);
	srm_debug(SRM_DEBUG_FILE, client->ipstr, "%s: SET EOF: relative=%d pos=%08lx\n", __func__,
		  whence, pos + 1);
	return 0;
}

static int get_lif_info(int fd, int32_t *out, uint16_t *gp, off_t *hdr_offset, int32_t *bdat_size)
{
	struct wshfs hdr;

	*hdr_offset = 0;
	*bdat_size = INT_MAX;

	if (read(fd, &hdr.hfs, sizeof(hdr.hfs)) != sizeof(hdr.hfs))
		return -1;

	if (be16toh(hdr.hfs.magic_8000) != 0x8000) {
		errno = EINVAL;
		return -1;
	}

	if (lseek(fd, be32toh(hdr.hfs.lif_offset) * LIF_BLOCK_SIZE, SEEK_SET) == -1)
		return -1;

	if (read(fd, &hdr.lif, sizeof(hdr.lif)) != sizeof(hdr.lif))
		return -1;

	*hdr_offset = be32toh(hdr.lif.lif.loc) * LIF_BLOCK_SIZE;
	*out = (int32_t)(int16_t)be16toh(hdr.lif.lif.type);
	if (gp) {
		gp[0] = hdr.lif.lif.gp[0];
		gp[1] = hdr.lif.lif.gp[1];
	}

	if (bdat_size && *out == HP300_FILETYPE_BDAT) {
		if (read(fd, &hdr.bdat, sizeof(hdr.bdat)) != sizeof(hdr.bdat))
			return -1;
		*bdat_size = be32toh(hdr.bdat.blocks) * 256 + be32toh(hdr.bdat.remainder);
	}
	return 0;
}

static void unix_to_srm_time(struct srm_date_type *srmtime, time_t *unixtime, int id)
{
	struct tm *tm = localtime(unixtime);
	srmtime->date = htons(((tm->tm_mon+1) << 12) | (tm->tm_mday << 7) | tm->tm_year);
	srmtime->seconds_since_midnight = htonl(tm->tm_hour * 3600 + tm->tm_min * 60 + tm->tm_sec);
	srmtime->id = htons(id);
}

static off_t srm_file_size(off_t size, off_t hdr_offset)
{
	if (size < hdr_offset)
		return 0;
	return (off_t)(size - hdr_offset);
}

static int srm_map_filetype(mode_t mode)
{
	if (S_ISREG(mode))
		return SRM_FILETYPE_REG_FILE;
	if (S_ISDIR(mode))
		return SRM_FILETYPE_DIRECTORY;
	if (S_ISFIFO(mode))
		return SRM_FILETYPE_PIPEFIFO;
	if (S_ISCHR(mode))
		return SRM_FILETYPE_CHARDEV;
	if (S_ISBLK(mode))
		return SRM_FILETYPE_BLOCKDEV;
	return SRM_FILETYPE_UNKNOWN;
}

static int get_file_info(struct srm_client *client, struct srm_volume *volume,
			 char *filename, struct srm_file_info *fi)

{
	srm_filetype_t filetype;
	int32_t lif_type, bdat_size;
	struct stat stbuf;
	off_t hdr_offset;
	uint16_t gp[2];
	char *p;

	if (srm_volume_lstat(client, volume, filename, &stbuf) == -1)
		return -1;

	fi->perm = htons(stbuf.st_mode & 0777);
	fi->open_flag = htonl(0);
	fi->max_file_size = htonl(INT_MAX);
	fi->share_code = -1;
	fi->capabilities = -1;

	filetype = srm_map_filetype(stbuf.st_mode);
	switch (filetype) {
	case SRM_FILETYPE_DIRECTORY:
		fi->file_code = htonl(HP300_FILETYPE_DIRECTORY);
		fi->record_mode = htonl(1);
		fi->share_code = htonl(1);
		fi->max_record_size = htonl(256);
		fi->logical_eof = htonl(1024);
		fi->physical_size = htonl(1);
		break;

	case SRM_FILETYPE_CHARDEV:
		fi->file_code = htonl(HP300_FILETYPE_CDEV);
		break;

	case SRM_FILETYPE_BLOCKDEV:
		fi->file_code = htonl(HP300_FILETYPE_BDEV);
		break;

	case SRM_FILETYPE_PIPEFIFO:
		fi->file_code = htonl(HP300_FILETYPE_PIPE);
		break;

	case SRM_FILETYPE_REMOTE_PROCESS:
	case SRM_FILETYPE_UNKNOWN:
		fi->file_code = htonl(HP300_FILETYPE_MISC);
		break;

	case SRM_FILETYPE_REG_FILE:
		fi->file_code = htonl(HP300_FILETYPE_UX);
		int fd = srm_volume_open_file(client, volume, filename, O_RDONLY);
		if (fd == -1)
			return -1;
		if (get_lif_info(fd, &lif_type, gp, &hdr_offset, &bdat_size) == -1)
			break;
		close(fd);
		fi->file_code = htonl(lif_type);
		fi->max_record_size = htonl(LIF_BLOCK_SIZE);
		fi->logical_eof = htonl(srm_file_size(stbuf.st_size, hdr_offset));
		fi->physical_size = htonl(srm_file_size(stbuf.st_size, hdr_offset));

		if (lif_type == HP300_FILETYPE_BDAT) {
			fi->max_record_size = gp[1] << 1;
			if (!fi->max_record_size)
				fi->max_record_size = 1;
			if (bdat_size < (int32_t)ntohl(fi->logical_eof))
				fi->logical_eof = htonl(bdat_size);
		}
		break;
	}

	fi->max_file_size = htonl(INT_MAX);
	fi->last_access.id = htons(stbuf.st_gid);
	fi->creation_date.id = htons(stbuf.st_uid);
	unix_to_srm_time(&fi->last_access, &stbuf.st_mtime, stbuf.st_gid);
	unix_to_srm_time(&fi->creation_date, &stbuf.st_ctime, stbuf.st_uid);

	if ((p = strrchr(filename, '/')))
		p++;
	else
		p = filename;
	c_string_to_srm(fi->filename, p);
	return 0;
}

static int handle_srm_fileinfo(struct srm_client *client,
			       struct srm_fileinfo *request,
			       struct srm_return_fileinfo *response,
			       int *responselen)
{
	int id = ntohl(request->file_id);
	struct open_file_entry *entry;

	entry = find_file_entry(client, id);
	if (!entry)
		return SRM_ERRNO_INVALID_FILE_ID;

	if (get_file_info(client, entry->volume, entry->filename->str, &response->fi) == -1)
		return errno_to_srm_error(client);

	srm_debug(SRM_DEBUG_REQUEST, client->ipstr, "%s: FILEINFO id=%08x file=%s\n",
		  __func__, id, entry ? entry->filename->str : "");
	*responselen = sizeof(struct srm_return_fileinfo);
	return 0;
}

static int handle_srm_close(struct srm_client *client,
			    struct srm_close *request)
{
	int id = ntohl(request->file_id);
	struct open_file_entry *entry;

	entry = find_file_entry(client, id);
	if (!entry)
		return SRM_ERRNO_INVALID_FILE_ID;

	g_tree_remove(client->files, &id);
	srm_debug(SRM_DEBUG_REQUEST, client->ipstr, "%s: CLOSE %08x\n", __func__, id);
	return 0;
}

static GString *srm_filename_from_fh(struct srm_file_header *fh,
				     struct srm_file_name_set *names,
				     int start)
{
	GString *ret = g_string_sized_new(128);

	for(unsigned int i = start; i < start + ntohl(fh->file_name_sets); i++) {
		g_string_append_c(ret, '/');
		char *s = names[i].file_name;
		int j = 0;
		while(*s != ' ' && *s != '<' && *s != '>' && j++ < 16)
			g_string_append_c(ret, *s++);
	}
	return ret;
}

static struct srm_volume *srm_volume_from_vh(struct srm_client *client,
					     struct srm_volume_header *vh,
					     int *error)
{
	struct srm_volume *volume;
	char *driver, *name, *cat;
	int addr, present;

	present = ntohl(vh->device_address_present);
	addr = ntohl(vh->device_address.address1);
	driver = srm_to_c_string(vh->driver_name);
	cat = srm_to_c_string(vh->catalogue_organization);
	name = srm_to_c_string(vh->volume_name);

	srm_debug(SRM_DEBUG_REQUEST, client->ipstr, "%s: present=%d, addr=%d, name='%s' driver='%s' cat='%s'\n", __func__,
		  present, addr, name, driver, cat);

	if (!present) {
		volume = get_volume_by_name(client, name);
		if (!volume) {
			srm_debug(SRM_DEBUG_FILE, client->ipstr, "%s: failed to get volume %s\n", __func__, name);
			*error = SRM_ERRNO_VOLUME_NOT_FOUND;
			goto error;
		}
	} else {
		volume = get_volume_by_index(client, addr);
		if (!volume) {
			srm_debug(SRM_DEBUG_FILE, client->ipstr, "%s: failed to get volume %d\n", __func__, addr);
			*error = SRM_ERRNO_VOLUME_NOT_FOUND;
			goto error;
		}
	}
error:
	free(driver);
	free(cat);
	free(name);
	return volume;
}

static GString *srm_get_filename(struct srm_client *client,
				 struct srm_volume *volume,
				 struct srm_file_header *fh,
				 struct srm_file_name_set *names,
				 int start, int *error)
{
	struct open_file_entry *entry;
	GString *ret, *filename;
	int wd = ntohl(fh->working_directory);

	ret = g_string_sized_new(128);
	if (wd) {
		entry = g_tree_lookup(client->files, &wd);
		if (!entry) {
			*error = SRM_ERRNO_INVALID_FILE_ID;
			return NULL;
		}
		g_string_append_printf(ret, "/%s", entry->filename->str);
	} else {
		g_string_append_printf(ret, "/%s", volume->path);
	}

	filename = srm_filename_from_fh(fh, names, start);
	if (filename->len)
		g_string_append_printf(ret, "/%s", filename->str);
	g_string_free(filename, TRUE);
	while(g_string_replace(ret, "//", "/", 0));
	if (path_levels(ret->str) < path_levels(volume->path)) {
		srm_debug(SRM_DEBUG_ERROR, client->ipstr, "request outside of volume: %s\n", ret->str);
		*error = SRM_ERRNO_FILE_PATHNAME_MISSING;
		g_string_free(ret, TRUE);
		return NULL;
	}
	return ret;
}

static int client_insert_file_entry(struct srm_client *client,
				    struct srm_volume *volume,
				    GString *filename,
				    int fd, off_t hdr_offset)
{
	struct open_file_entry *entry = g_new0(struct open_file_entry, 1);
	int file_id;

	entry->filename = filename;
	entry->fd = fd;
	entry->hdr_offset = hdr_offset;
	entry->volume = volume;

	do {
		file_id = g_random_int();
	} while(!file_id || g_tree_lookup(client->files, &file_id));

	entry->client_fd = file_id;

	g_tree_insert(client->files, &entry->client_fd, entry);
	return file_id;
}

static int handle_srm_open(struct srm_client *client,
			   struct srm_open *request,
			   struct srm_return_open *response,
			   int *responselen)
{
	srm_filetype_t filetype, opentype;
	int32_t lif_type, bdat_size;
	struct srm_volume *volume;
	struct stat stbuf = { 0 };
	int fd = -1, error = 0;
	off_t hdr_offset = 0;
	GString *filename;
	uint16_t gp[2];

	opentype = ntohl(request->open_type);

	srm_debug(SRM_DEBUG_REQUEST, client->ipstr, "%s: share_code %x, open_type: %x pad: %x %x %x\n", __func__,
		  ntohl(request->share_code), opentype,
		  ntohl(request->__pad0), ntohl(request->__pad1), ntohl(request->__pad2));

	volume = srm_volume_from_vh(client, &request->vh, &errno);
	if (!volume) {
		error = SRM_ERRNO_VOLUME_NOT_FOUND;
		goto error;
	}

	filename = srm_get_filename(client, volume, &request->fh,
				    request->filenames, 0, &errno);
	if (!filename) {
		error = SRM_ERRNO_FILE_PATHNAME_MISSING;
		goto error;
	}

	if (srm_volume_lstat(client, volume, filename->str, &stbuf) == -1) {
		error = errno_to_srm_error(client);
		goto error;
	}

	filetype = srm_map_filetype(stbuf.st_mode);

	if (opentype == SRM_FILETYPE_DIRECTORY && opentype != filetype) {
		error = SRM_ERRNO_FILE_NOT_DIRECTORY;
		goto error;
	}

	response->share_bits = htonl(0xffffffff);
	switch(filetype) {
	case SRM_FILETYPE_DIRECTORY:
		fd = srm_volume_open_file(client, volume, filename->str, O_DIRECTORY);
		if (fd == -1) {
			error = errno_to_srm_error(client);
			break;
		}
		response->file_code = ntohl(3);
		response->record_mode = ntohl(1);
		response->max_record_size = ntohl(LIF_BLOCK_SIZE);
		break;

	case SRM_FILETYPE_CHARDEV:
	case SRM_FILETYPE_BLOCKDEV:
	case SRM_FILETYPE_PIPEFIFO:
	case SRM_FILETYPE_REG_FILE:
		response->file_code = htonl(HP300_FILETYPE_UX);
		switch (ntohs(request->open_type)) {
		case SRM_OPENTYPE_RDWR:
			fd = srm_volume_open_file(client, volume, filename->str, O_RDWR);
			if (fd != -1)
				break;
			/* fallthrough */
		case SRM_OPENTYPE_RDONLY:
			fd = srm_volume_open_file(client, volume, filename->str, O_RDONLY);
			break;
		default:
			error = SRM_ERRNO_ACCESS_TO_FILE_NOT_ALLOWED;
			break;
		}

		if (fd == -1) {
			error = errno_to_srm_error(client);
			break;
		}

		if (filetype != SRM_FILETYPE_REG_FILE)
			break;

		if (get_lif_info(fd, &lif_type, gp, &hdr_offset, &bdat_size) == -1) {
			error = errno_to_srm_error(client);
			break;
		}

		if (lseek(fd, stbuf.st_size, SEEK_SET) == -1) {
			error = errno_to_srm_error(client);
			break;
		}

		response->gp[0] = gp[0];
		response->gp[1] = gp[1];
		response->file_code = htonl(lif_type);
		response->open_logical_eof = htonl(stbuf.st_size - hdr_offset);
		response->sec_ext_size = htonl(stbuf.st_size - hdr_offset);
		if (lif_type == HP300_FILETYPE_BDAT && bdat_size < (int32_t)ntohl(response->open_logical_eof))
			response->open_logical_eof = htonl(bdat_size);
		response->max_file_size = htonl(INT_MAX);
		response->max_record_size = htonl(LIF_BLOCK_SIZE);
		break;

	case SRM_FILETYPE_UNKNOWN:
	case SRM_FILETYPE_REMOTE_PROCESS:
		error = SRM_ERRNO_FILE_NOT_FOUND;
		break;

		response->record_mode = 0;
		response->file_code = htonl(0xffffe94b);
		break;
	}
	if (!error)
		response->file_id = htonl(client_insert_file_entry(client, volume, filename, fd, hdr_offset));
error:
	srm_debug(SRM_DEBUG_REQUEST, client->ipstr, "%s: OPEN file='%s' fd=%d id=%08x hdrsz=%ld error=%d\n",
		  __func__, filename ? filename->str : "", fd, ntohl(response->file_id), hdr_offset, error);
	if (filename && error)
		g_string_free(filename, TRUE);
	*responselen = sizeof(*response);
	return error;
}

static int srm_dir_compare(const void *a, const void *b)
{
	return strcmp(a, b);
}

static int handle_srm_catalog(struct srm_client *client,
			      struct srm_catalog *request,
			      struct srm_return_catalog *response,
			      int *responselen)
{
	int error = SRM_ERRNO_NO_ERROR;
	struct dirent *dirent = NULL;
	struct srm_volume *volume;
	GString *filename = NULL;
	srm_filetype_t filetype;
	int start, max, cnt = 0;
	GList *names = NULL;
	struct stat stbuf;
	DIR *dir;

	max = ntohl(request->max_num_files);
	start = ntohl(request->file_index);
	volume = srm_volume_from_vh(client, &request->vh, &error);
	if (!volume)
		goto error;

	filename = srm_get_filename(client, volume, &request->fh,
				    request->filenames, 0, &error);
	if (!filename)
		goto error;

	if (srm_volume_lstat(client, volume, filename->str, &stbuf) == -1) {
		error = errno_to_srm_error(client);
		goto error;
	}

	filetype = srm_map_filetype(stbuf.st_mode);
	switch(filetype) {
	case SRM_FILETYPE_DIRECTORY:
		dir = opendir(filename->str);
		if (!dir) {
			error = errno_to_srm_error(client);
			break;
		}

		while ((dirent = readdir(dir)))
			names = g_list_insert_sorted(names, g_strdup(dirent->d_name), srm_dir_compare);
		closedir(dir);

		if (start < 1)
			start = 1;

		GList *p = g_list_nth(names, start - 1);
		for (cnt = 0;  p && cnt < max; p = g_list_next(p)) {
			GString *fullname = g_string_new(filename->str);
			g_string_append_printf(fullname, "/%s", (char *)p->data);
			if (!get_file_info(client, volume, fullname->str, &response->fi[cnt]))
				cnt++;
			g_string_free(fullname, TRUE);
		}
		g_list_free_full(names, free);
		response->num_files = htonl(cnt);
		break;

	case SRM_FILETYPE_REG_FILE:
		if (get_file_info(client, volume, filename->str, &response->fi[0]) == -1) {
			error = SRM_ERRNO_VOLUME_IO_ERROR;
			break;
		}
		response->num_files = htonl(1);
		break;

	case SRM_FILETYPE_BLOCKDEV:
		response->fi[0].file_code = htonl(HP300_FILETYPE_BDEV);
		response->num_files = htonl(1);
		break;

	case SRM_FILETYPE_CHARDEV:
		response->fi[0].file_code = htonl(HP300_FILETYPE_CDEV);
		response->num_files = htonl(1);
		break;

	case SRM_FILETYPE_PIPEFIFO:
		response->fi[0].file_code = htonl(HP300_FILETYPE_PIPE);
		response->num_files = htonl(1);
		break;

	case SRM_FILETYPE_UNKNOWN:
	case SRM_FILETYPE_REMOTE_PROCESS:
		response->fi[0].file_code = htonl(HP300_FILETYPE_MISC);
		response->num_files = htonl(1);
		break;
	}
error:
	srm_debug(SRM_DEBUG_REQUEST, client->ipstr, "%s: CAT '%s' start=%d max=%d wd=%x results=%d error=%d\n",
		  __func__, filename ? filename->str : "", start, max, ntohl(request->fh.working_directory),
		  cnt, error);
	if (filename)
		g_string_free(filename, TRUE);
	*responselen = sizeof(*response);
	return error;
}

static int srm_write_hfslif_header(struct srm_create_file *request, int fd)
{
	struct wshfs hdr;
	int32_t type = ntohl(request->file_code);
	int max_record_size = ntohl(request->max_record_size);
	int first_extend = ntohl(request->first_extent);
	ssize_t ret;

	memset(&hdr, 0, sizeof(hdr));

	hdr.hfs.magic_8000 = htobe16(0x8000);
	hdr.hfs.lif_offset = htobe32(1);
	hdr.hfs.field_0x0c = htobe16(0x1000);
	hdr.hfs.field_0x10 = htobe32(1);
	hdr.hfs.field_0x18 = htobe32(1);
	hdr.hfs.field_0x1c = htobe32(1);
	hdr.hfs.field_0x20 = htobe32(3);
	memcpy(hdr.hfs.hfslif, "HFSLIF", 6);
	memset(hdr.hfs.magic_0x24, 0x11, sizeof(hdr.hfs.magic_0x24));
	memset(hdr.hfs.magic_0xf8, 0x11, sizeof(hdr.hfs.magic_0xf8));
	memcpy(hdr.lif.lif.name, "WS_FILE   ", 10);
	hdr.lif.lif.type = htobe16(type & 0xffff);
	hdr.lif.field_0x2a = 0xffff;
	hdr.lif.lif.loc = htobe32(2);
	hdr.lif.lif.volnr = htobe16(0x8001);
	hdr.lif.lif.tim0 = 0x2020;
	hdr.lif.lif.tim1 = 0x2020;
	hdr.lif.lif.tim2 = 0x2020;

	switch (type) {
	case HP300_FILETYPE_BDAT:
		if (max_record_size < 1 || (max_record_size > 1 && (max_record_size & 1))) {
			errno = EINVAL;
			return -1;
		}
		hdr.lif.lif.gp[0] = request->gp[0];
		if ((max_record_size >> 1) < 0 && (max_record_size & 1))
			hdr.lif.lif.gp[1] = htobe32(max_record_size / 2 + 1);
		else
			hdr.lif.lif.gp[1] = htobe32(max_record_size / 2);
		first_extend += LIF_BLOCK_SIZE - 1;
		first_extend &= ~LIF_BLOCK_SIZE;
		hdr.lif.lif.size = htobe32(first_extend);
		/* TODO: first extent logic */
		break;

	case HP300_FILETYPE_BASIC_BIN:
	case HP300_FILETYPE_BASIC_PROG:
		hdr.lif.lif.gp[0] = request->gp[0];
		hdr.lif.lif.gp[1] = htobe16(0x80);
		break;
	case 1:
		hdr.lif.lif.gp[0] = 0;
		hdr.lif.lif.gp[1] = htobe16(0x80);
		break;
	default:
		hdr.lif.lif.gp[0] = request->gp[0];
		hdr.lif.lif.gp[1] = request->gp[1];
		break;
	}
	ret = write(fd, &hdr, sizeof(hdr));
	if (ret == -1)
		return -1;
	if (ret != sizeof(hdr)) {
		errno = EIO;
		return -1;
	}
	return 0;
}

static int handle_srm_createfile(struct srm_client *client,
				 struct srm_create_file *request)
{
	int fd = -1, type, error = 0;
	struct srm_volume *volume;
	GString *filename;

	type = ntohl(request->file_code);
	volume = srm_volume_from_vh(client, &request->vh, &error);
	if (!volume)
		goto error;
	filename = srm_get_filename(client, volume, &request->fh,
				    request->filenames, 0, &error);
	if (!filename)
		return SRM_ERRNO_FILE_PATHNAME_MISSING;
	if (type == 3) {
		if (srm_volume_mkdir(client, volume, filename->str) == -1)
			error = errno_to_srm_error(client);
	} else {
		fd = srm_volume_open_file(client, volume, filename->str, O_WRONLY|O_TRUNC|O_CREAT);
		if (fd == -1) {
			error = errno_to_srm_error(client);
			goto error;
		}
		if (srm_write_hfslif_header(request, fd) == -1) {
			error = errno_to_srm_error(client);
			goto error;
		}
	}
error:
	if (fd != -1)
		close(fd);
	srm_debug(SRM_DEBUG_REQUEST, client->ipstr, "%s: CREATE FILE: filename='%s' %08x\n", __func__, filename->str, type);
	g_string_free(filename, TRUE);
	return error;
}

static int handle_srm_create_link(struct srm_client *client,
				  struct srm_create_link *request)
{
	GString *old_filename = NULL, *new_filename = NULL;
	struct srm_volume *volume;
	int error, purge, err;

	purge = ntohl(request->purge_old_link);
	volume = srm_volume_from_vh(client, &request->vh, &error);
	if (!volume)
		goto error;

	old_filename = srm_get_filename(client, volume, &request->fh_old,
					request->filenames,
					0, &error);
	if (!old_filename)
		goto error;

	new_filename = srm_get_filename(client, volume, &request->fh_new,
					request->filenames,
					ntohl(request->fh_old.file_name_sets), &error);
	if (!new_filename)
		goto error;

	if (purge)
		err = srm_volume_rename(client, volume, old_filename->str,
					new_filename->str);
	else
		err = srm_volume_link(client, volume, old_filename->str,
				      new_filename->str);

	error = err ? errno_to_srm_error(client) : 0;
error:
	srm_debug(SRM_DEBUG_REQUEST, client->ipstr, "%s: CREATELINK %s -> %s, purge %d, error %d\n", __func__,
		  old_filename ? old_filename->str : "",
		  new_filename ? new_filename->str : "", purge, error);
	if (old_filename)
		g_string_free(old_filename, TRUE);
	if (new_filename)
		g_string_free(new_filename, TRUE);
	return error;
}

static int handle_srm_volstatus(struct srm_client *client,
				struct srm_volume_status *request,
				struct srm_return_volume_status *response,
				int *responselen)
{
	struct srm_volume *volume;
	int error = SRM_ERRNO_NO_ERROR;
	struct statfs statfsbuf;
	unsigned long long bytesfree;

	*responselen = sizeof(*response);
	volume = srm_volume_from_vh(client, &request->vh, &error);
	if (volume) {
		if (statfs(volume->path, &statfsbuf) == -1) {
			error = errno_to_srm_error(client);
		} else {
			c_string_to_srm(response->volname, volume->name);

			response->exist = 1;
			response->srmux = 1;
			bytesfree = statfsbuf.f_bavail * statfsbuf.f_bsize;
			response->freesize = htonl(MIN(INT_MAX, bytesfree));
		}
	}
	srm_debug(SRM_DEBUG_REQUEST, client->ipstr, "%s: VOLSTATUS vname='%s' error=%d\n",
		  __func__, volume ? volume->name : "", error);
	return error;
}

static int handle_srm_purgelink(struct srm_client *client,
				struct srm_purge_link *request)
{
	int error = SRM_ERRNO_NO_ERROR;
	struct srm_volume *volume;
	GString *filename;

	volume = srm_volume_from_vh(client, &request->vh, &error);
	if (!volume)
		goto error;

	filename = srm_get_filename(client, volume,
				    &request->fh,
				    request->filenames, 0, &error);
	if (!filename)
		goto error;

	if (srm_volume_unlink_file(client, volume, filename->str) == -1)
		error = errno_to_srm_error(client);
error:
	srm_debug(SRM_DEBUG_REQUEST, client->ipstr, "%s: PURGE LINK %s error=%d\n",
		  __func__,filename->str, error);
	g_string_free(filename, TRUE);
	return error;
}

static int handle_srm_change_protect(struct srm_client *client)
{

	srm_debug(SRM_DEBUG_REQUEST, client->ipstr, "%s: CHANGE PROTECT\n", __func__);
	return SRM_ERRNO_VOLUME_IO_ERROR;
}

static int handle_srm_xchg_open(struct srm_client *client,
				struct srm_xchg_open *request)
{
	(void)request;
	(void)client;

	return SRM_ERRNO_VOLUME_IO_ERROR;
}

static char *srm_request_to_name(srm_request_t type)
{
	switch(type)
	{
	case SRM_REQ_READ:
		return "READ";
	case SRM_REQ_WRITE:
		return "WRITE";
	case SRM_REQ_POSITION:
		return "POSITION";
	case SRM_REQ_SET_EOF:
		return "SET_EOF";
	case SRM_REQ_FILEINFO:
		return "FILEINFO";
	case SRM_REQ_CLOSE:
		return "CLOSE";
	case SRM_REQ_OPEN:
		return "OPEN";
	case SRM_REQ_CATALOG:
		return "CATALOG";
	case SRM_REQ_CREATEFILE:
		return "CREATEFILE";
	case SRM_PURGE_LINK:
		return "PURGELINK";
	case SRM_REQ_CHANGE_PROTECT:
		return "CHANGEPROTECT";
	case SRM_REQ_CREATELINK:
		return "CREATELINK";
	case SRM_REQ_XCHG_OPEN:
		return "XCHGOPEN";
	case SRM_REQ_VOLSTATUS:
		return "VOLSTATUS";
	case SRM_REQ_RESET:
		return "RESET";
	case SRM_REQ_COPY_FILE:
		return "COPYFILE";
	case SRM_REQ_AREYOUALIVE:
		return "AREYOUALIVE";
	case SRM_REQ_EXECUTE_CMD:
		return "EXECUTECMD";
	default:
		return "UNKNOWN";
	}
}

static char *srm_strerror(srm_errno_t error)
{
	switch(error) {
	case SRM_ERRNO_NO_ERROR:
		return "No error";
	case SRM_ERRNO_SOFTWARE_BUG:
		return "Software Bug";
	case SRM_ERRNO_BAD_SELECT_CODE:
		return "Bad select code";
	case SRM_ERRNO_UNALLOCATED_EXTENT:
		return "Unallocated extend";
	case SRM_ERRNO_DS_ROM_MISSING:
		return "DS ROM missing";
	case SRM_ERRNO_UNSUPPORTED_DAM:
		return "Unsupported DAM";
	case SRM_ERRNO_DEVICE_DRIVERS_DONT_MATCH:
		return "Device drivers dont match";
	case SRM_ERRNO_INVALID_IOS_REQUEST:
		return "Invalid IOS request";
	case SRM_ERRNO_ATTACH_TABLE_FULL:
		return "Attach Table full";
	case SRM_ERRNO_IMPROPER_MASS_STORAGE_DEVICE:
		return "Improper mass storage device";
	case SRM_ERRNO_DIRECTORY_FORMATS_DONT_MATCH:
		return "Directory formats don't match";
	case SRM_ERRNO_INVALID_FILE_SIZE:
		return "Invalid file size";
	case SRM_ERRNO_INVALID_FILE_ID:
		return "Invalid file ID";
	case SRM_ERRNO_VOLUME_RECOVERABLE_ERROR:
		return "Volume recoverable error";
	case SRM_ERRNO_VOLUME_IO_ERROR:
		return "Volume I/O error";
	case SRM_ERRNO_FILE_PATHNAME_MISSING:
		return "File/Pathname missing";
	case SRM_ERRNO_ILLEGAL_BYTE_NUMBER:
		return "Illegal byte number";
	case SRM_ERRNO_CORRUPT_DIRECTORY:
		return "Corrupt directory";
	case SRM_ERRNO_SUCCESSFUL_COMPLETION:
		return "Successful Completion";
	case SRM_ERRNO_SYSTEM_DOWN:
		return "System Down";
	case SRM_ERRNO_FILE_UNOPENED:
		return "File unopened";
	case SRM_ERRNO_VOLUME_OFFLINE:
		return "Volume offline";
	case SRM_ERRNO_VOLUME_LABELS_DONT_MATCH:
		return "Volume labels don't match";
	case SRM_ERRNO_PASSWORD_NOT_ALLOWED:
		return "Password not allowed";
	case SRM_ERRNO_ACCESS_TO_FILE_NOT_ALLOWED:
		return "Access to file not allowed";
	case SRM_ERRNO_UNSUPPORTED_DIRECTORY_OPERATION:
		return "Unsupported directory operation";
	case SRM_ERRNO_CONFLICTING_SHARE_MODES:
		return "Conflicting share modes";
	case SRM_ERRNO_BAD_FILE_NAME:
		return "Bad file name";
	case SRM_ERRNO_FILE_IN_USE:
		return "File in use";
	case SRM_ERRNO_INSUFFICIENT_DISK_SPACE:
		return "Insufficient disk space";
	case SRM_ERRNO_DUPLICATE_FILENAMES:
		return "Duplicate Filenames";
	case SRM_ERRNO_PHYS_EOF_ENCOUNTERED:
		return "Physical EOF encountered";
	case SRM_ERRNO_NO_CAPABILITY_FOR_FILE:
		return "No capability for file";
	case SRM_ERRNO_FILE_NOT_FOUND:
		return "File not found";
	case SRM_ERRNO_VOLUME_IN_USE:
		return "Volume in use";
	case SRM_ERRNO_FILE_NOT_DIRECTORY:
		return "File not directory";
	case SRM_ERRNO_DIRECTORY_NOT_EMPTY:
		return "Directory not empty";
	case SRM_ERRNO_VOLUME_NOT_FOUND:
		return "Volume not found";
	case SRM_ERRNO_INVALID_PROTECT_CODE:
		return "Invalid Protect Code";
	case SRM_ERRNO_VOLUME_UNRECOVERABLE_ERROR:
		return "Volume unrecoverable error";
	case SRM_ERRNO_PASSWORD_NOT_FOUND:
		return "Password not found";
	case SRM_ERRNO_DUPLICATE_PASSWORDS:
		return "Duplicate Passwords";
	case SRM_ERRNO_DEADLOCK_DETECTED:
		return "Deadlock detected";
	case SRM_ERRNO_LINK_TO_DIRECTORY_NOT_ALLOWED:
		return "Link to directory not allowed";
	case SRM_ERRNO_RENAME_ACROSS_VOLUMES:
		return "Rename across volumes";
	case SRM_ERRNO_VOLUME_DOWN:
		return "Volume down";
	case SRM_ERRNO_EOF_ENCOUNTERED:
		return "EOF encountered";
	case SRM_ERRNO_INVALID_FILE_CODE:
		return "Invalid file code";
	case SRM_ERRNO_FILE_LOCKED_PLEASE_RETRY:
		return "File locked, please retry";
	case SRM_ERRNO_NO_REPLY:
		return "No reply";
	case SRM_ERRNO_PURGE_ON_OPEN:
		return "Purge on open";
	case SRM_ERRNO_ERROR_TOP:
		return "";
	}
	return "Unknown error";
}

size_t srm_handle_request(struct srm_client *client,
			  struct srm_request_packet *request,
			  struct srm_response_packet *response)
{
	srm_errno_t ret = SRM_ERRNO_VOLUME_IO_ERROR;
	int responselen = 8, level = 7;
	struct srm_return_empty *empty;
	srm_request_t type;

	type = ntohl(request->hdr.request_type);
	switch(type) {
	case SRM_REQ_RESET:
		ret = handle_srm_reset(client);
		level = 2;
		break;

	case SRM_REQ_AREYOUALIVE:
		ret = handle_srm_areyoualive();
		level = 2;
		break;

	case SRM_REQ_WRITE:
		ret = handle_srm_write(client, (void *)request->payload,
				       (void *)response->payload, &responselen);
		break;

	case SRM_REQ_POSITION:
		ret = handle_srm_position(client, (void *)request->payload);
		break;

	case SRM_REQ_READ:
		ret = handle_srm_read(client, (void *)request->payload,
				      (void *)response->payload, &responselen);
		break;

	case SRM_REQ_SET_EOF:
		ret = handle_srm_set_eof(client, (void *)request->payload);
		break;

	case SRM_REQ_FILEINFO:
		ret = handle_srm_fileinfo(client, (void *)request->payload,
					  (void *)response->payload, &responselen);
		break;

	case SRM_REQ_CLOSE:
		ret = handle_srm_close(client, (void *)request->payload);
		break;

	case SRM_REQ_OPEN:
		ret = handle_srm_open(client, (void *)request->payload,
				      (void *)response->payload, &responselen);
		break;

	case SRM_REQ_CATALOG:
		ret = handle_srm_catalog(client, (void *)request->payload,
					 (void *)response->payload, &responselen);
		break;

	case SRM_REQ_CREATEFILE:
		ret = handle_srm_createfile(client, (void *)request->payload);
		break;

	case SRM_REQ_CREATELINK:
		ret = handle_srm_create_link(client, (void *)request->payload);
		break;

	case SRM_REQ_VOLSTATUS:
		ret = handle_srm_volstatus(client, (void *)request->payload,
					   (void *)response->payload, &responselen);
		break;

	case SRM_PURGE_LINK:
		ret = handle_srm_purgelink(client, (void *)request->payload);
		break;

	case SRM_REQ_CHANGE_PROTECT:
		ret = handle_srm_change_protect(client);
		break;

	case SRM_REQ_XCHG_OPEN:
		ret = handle_srm_xchg_open(client, (void *)request->payload);
		break;

	default:
		srm_debug(SRM_DEBUG_REQUEST, client->ipstr, "%s: unknown request %d\n",
			__func__, ntohl(request->hdr.request_type));
		break;
	}

	responselen += sizeof(struct srm_return_header);

	empty = (void *)response->payload;
	empty->status = htonl(ret);

	response->hdr.message_length = htonl(responselen);
	response->hdr.return_request_type = htonl(-htonl(request->hdr.request_type));
	response->hdr.user_sequencing_field = request->hdr.user_sequencing_field;
	response->hdr.level = level;
	srm_debug(SRM_DEBUG_RESPONSE, client->ipstr, "%s = %s (%d), sequence = %x\n",
		  srm_request_to_name(type), srm_strerror(ret), ret, ntohl(request->hdr.user_sequencing_field));
	return responselen;
}


static int srm_send(struct srm_client *client, struct srm_epoll_ctx *ctx, struct sockaddr_in *addr)
{
	ssize_t ret;

	if (!addr)
		addr = &bcaddr;

	srm_debug(SRM_DEBUG_RESPONSE, client->ipstr, "sending %zd bytes\n", ctx->outlen);
	ret = sendto(ctx->fd, ctx->outbuf, ctx->outlen, 0,
		     (struct sockaddr *)addr, sizeof(*addr));
	if (ret == -1) {
		if (errno != EAGAIN) {
			srm_debug(SRM_DEBUG_ERROR, client->ipstr, "sendto: %m\n");
			return -1;
		}

		if (epoll_set_events(ctx->fdctx, EPOLLOUT) == -1) {
			srm_debug(SRM_DEBUG_ERROR, client->ipstr, "epoll_set_events: %m\n");
			return -1;
		}
		return 0;
	}

	if (ret != ctx->outlen) {
		srm_debug(SRM_DEBUG_ERROR, client->ipstr, "sendto: only wrote %zd out of %zd bytes\n",
			  ret, ctx->outlen);
		return -1;
	}
	ctx->outlen = 0;
	epoll_clear_events(ctx->fdctx, EPOLLOUT);
	return 0;
}

static void handle_srm_xfer(struct srm_epoll_ctx *ctx,
			    struct srm_client *client,
			    size_t len)
{
	struct lansrm_response_packet *response = ctx->outbuf;
	struct lansrm_request_packet *request = ctx->inbuf;
	struct srm_transfer *xfer = &request->xfer;
	size_t srmlen, rlen = 0;

	srm_debug(SRM_DEBUG_XFER, client->ipstr, "%s: session=%d, version=%d, host_node=%d, unum=%d, sequence_no=%d\n",
		__func__, ntohs(xfer->session_id), ntohs(xfer->version),
		ntohs(xfer->host_node), xfer->unum, xfer->sequence_no);

	if (len < offsetof(struct lansrm_request_packet, srm.payload)) {
		response->xfer.ret_code = htons(5); // BAD SIZE
		goto send;
	}
	hexdump(SRM_DEBUG_PACKET_RX, client->ipstr, "RX XFR", &request->xfer, sizeof(request->xfer));
	hexdump(SRM_DEBUG_PACKET_RX, client->ipstr, "RX HDR", &request->srm.hdr, sizeof(request->srm.hdr));

	srmlen = len - offsetof(struct lansrm_request_packet, srm);
	if (srmlen < ntohl(request->srm.hdr.message_length)) {
		srm_debug(SRM_DEBUG_ERROR, client->ipstr, "bad srm message size: %zd < %d\n",
			  srmlen, ntohl(request->srm.hdr.message_length));
		response->xfer.ret_code = htons(5); // BAD SIZE
		goto send;
	}
	hexdump(SRM_DEBUG_PACKET_RX, client->ipstr, "RX DAT", &request->srm.payload, srmlen);
	rlen = srm_handle_request(client, &request->srm, &response->srm);
send:
	memcpy(&response->xfer, &request->xfer, sizeof(struct srm_transfer));
	response->xfer.rec_type = htons(SRM_REPLY_XFER);
	hexdump(SRM_DEBUG_PACKET_RX, client->ipstr, "TX XFR", &response->xfer, sizeof(response->xfer));
	hexdump(SRM_DEBUG_PACKET_RX, client->ipstr, "TX HDR", &response->srm.hdr, sizeof(response->srm.hdr));
	hexdump(SRM_DEBUG_PACKET_RX, client->ipstr, "TX DAT", &response->srm.payload, rlen);

	rlen += sizeof(struct srm_transfer);
	ctx->outlen = rlen;
	srm_send(client, ctx, &client->addr);
}

static int lansrm_file_compare(const void *a, const void *b, void *data)
{
	const int *filea = a;
	const int *fileb = b;
	(void)data;

	return *filea - *fileb;
}

static int srm_connect_fill_ip_node(struct srm_connect_reply *reply,
				    struct srm_client *client,
				    char *hwaddr_string)
{
	struct in_addr clientaddr, hostaddr;
	gchar *tmp;
	int ret;

	if (hwaddr_string) {
		tmp = g_key_file_get_string(config.keyfile, "global", hwaddr_string, NULL);
		if (!tmp) {
			srm_debug(SRM_DEBUG_CONNECT, client->ipstr, "unknown client %s\n", hwaddr_string);
			return -1;
		}
		ret = inet_pton(AF_INET, tmp, &clientaddr);
		if (ret != 1) {
			srm_debug(SRM_DEBUG_FILE, client->ipstr, "Failed to parse IP %s\n", tmp);
			g_free(tmp);
			return -1;
		}
		client->addr.sin_addr.s_addr = clientaddr.s_addr;
		client->ipstr = g_strdup(tmp);
		g_free(tmp);
	}

	tmp = g_key_file_get_string(config.keyfile, "global", "hostip", NULL);
	if (!tmp) {
		srm_debug(SRM_DEBUG_CONNECT, client->ipstr, "no hostip set in global section\n");
		return -1;
	}
	ret = inet_pton(AF_INET, tmp, &hostaddr);
	g_free(tmp);
	if (ret != 1) {
		srm_debug(SRM_DEBUG_FILE, client->ipstr, "Failed to parse IP %s\n", tmp);
		g_free(tmp);
		return -1;
	}

	if (reply) {
		reply->my_ip = clientaddr.s_addr;
		reply->host_ip = hostaddr.s_addr;
		reply->my_node = htons(g_key_file_get_integer(config.keyfile, client->ipstr, "node", NULL));
	}
	return 0;
}

static void client_file_free(gpointer data)
{
	struct open_file_entry *entry = data;

	g_string_free(entry->filename, TRUE);
	close(entry->fd);
	g_free(entry);
}

static void srm_client_free(struct srm_client *client)
{
	if (!client)
		return;
	if (client->files)
		g_tree_destroy(client->files);
	g_free(client);
}

static struct srm_client *srm_new_client(GTree *clients, struct sockaddr_in *addr,
					 socklen_t addrlen, char *hwaddr_string,
					 struct srm_connect_reply *reply)
{
	struct srm_client *client = g_new0(struct srm_client, 1);

	memcpy(&client->addr, addr, addrlen);
	if (srm_connect_fill_ip_node(reply, client, hwaddr_string) == -1) {
		g_free(client);
		return NULL;
	}
	client->files = g_tree_new_full(lansrm_file_compare, NULL, NULL, client_file_free);
	client->config = get_client_config(&client->addr);
	if (!client->config) {
		srm_client_free(client);
		return NULL;
	}
	g_tree_replace(clients, &client->addr, client);
	return client;
}

static void srm_reject_client_xfer(struct srm_epoll_ctx *ctx, char *name)
{
	struct srm_transfer *request = ctx->outbuf;
	struct srm_transfer *reply = ctx->outbuf;

	srm_debug(SRM_DEBUG_ERROR, NULL, "reject XFER from %s\n", name);
	memcpy(reply, request, sizeof(*reply));
	request->ret_code = htons(4);
	request->rec_type = htons(SRM_REPLY_XFER);
	ctx->outlen = sizeof(*reply);
	srm_send(NULL, ctx, &ctx->addr);
}

static void srm_reject_client_connect(struct srm_epoll_ctx *ctx, char *name,
				      struct sockaddr_in *addr)
{
	struct srm_connect_request *request = ctx->inbuf;
	struct srm_connect_reply *reply = ctx->outbuf;

	srm_debug(SRM_DEBUG_ERROR, NULL, "reject CONNECT from %s\n", name);
	memcpy(reply, request, sizeof(*reply));
	reply->ret_code = htons(4);
	reply->rec_type = htons(SRM_REPLY_CONNECT);
	ctx->outlen = sizeof(*reply);
	srm_send(NULL, ctx, addr);
}

static void handle_srm_connect(struct srm_epoll_ctx *ctx, char *ipstr,
			       struct sockaddr_in *addr)
{
	struct srm_connect_request *req = ctx->inbuf;
	struct srm_connect_reply *reply = ctx->outbuf;
	uint8_t *hwaddr = req->station;
	char hwaddr_string[32] = { 0 };
	struct srm_client *client;

	memset(reply, 0, sizeof(*reply));

	snprintf(hwaddr_string, sizeof(hwaddr_string)-1, "%02x:%02x:%02x:%02x:%02x:%02x",
		 hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);

	client = srm_new_client(ctx->clients, &ctx->addr, ctx->addrlen, hwaddr_string, reply);
	srm_debug(SRM_DEBUG_CONNECT, client->ipstr, "%s: code=%d, option=%d, node=%d, version=%d, station=%s host=%s\n",
		  __func__, ntohs(req->ret_code), ntohs(req->option_code),
		  ntohs(req->host_node), ntohs(req->version),
		  hwaddr_string, ipstr);

	if (!client) {
		srm_reject_client_connect(ctx, hwaddr_string, addr);
		return;
	}

	memcpy(reply->my_station, req->station, sizeof(reply->my_station));
	reply->rec_type = htons(SRM_REPLY_CONNECT);
	reply->ret_code = 0;
	reply->host_flag = 0;
	reply->version = htons(11);

	ctx->outlen = sizeof(*reply);
	srm_send(client, ctx, NULL);
	return;
}

static void handle_rx(struct srm_epoll_ctx *ctx)
{
	struct lansrm_request_packet *packet = ctx->inbuf;
	struct srm_client *client = NULL;
	GTree *clients = ctx->clients;
	char ipstr[INET_ADDRSTRLEN];
	size_t len = ctx->inlen;

	if (!inet_ntop(AF_INET, &ctx->addr.sin_addr.s_addr, ipstr, ctx->addrlen)) {
		srm_debug(SRM_DEBUG_PACKET_RX, NULL, "%s: inet_ntop: %m\n", __func__);
		return;
	}

	switch (ntohs(packet->xfer.rec_type)) {
	case SRM_REQUEST_CONNECT:
		if (len < sizeof(struct srm_connect_request)) {
			srm_debug(SRM_DEBUG_ERROR, NULL, "short srm request: %zd bytes\n", len);
			break;
		}
		handle_srm_connect(ctx, ipstr, &ctx->addr);
		break;

	case SRM_REQUEST_XFER:
		if (len < sizeof(struct srm_transfer)) {
			srm_debug(SRM_DEBUG_ERROR, NULL, "short srm request: %zd bytes\n", len);
			break;
		}
		client = g_tree_lookup(clients, &ctx->addr);
		if (!client) {
			if (!g_key_file_get_boolean(config.keyfile, "global", "accept_unknown", NULL)) {
				srm_debug(SRM_DEBUG_ERROR, client->ipstr, "client without connect: %s\n", ipstr);
				srm_reject_client_xfer(ctx, ipstr);
				break;
			}
			client = srm_new_client(clients, &ctx->addr, ctx->addrlen, NULL, NULL);
			if (!client) {
				srm_reject_client_xfer(ctx, ipstr);
				break;
			}
			client->ipstr = g_strdup(ipstr);
			memcpy(&client->addr, &ctx->addr, sizeof(struct sockaddr_in));
		}
		handle_srm_xfer(ctx, client, len);
		if (client->cleanup)
			g_tree_remove(clients, client);
		break;

	case SRM_REPLY_XFER:
	case SRM_REPLY_CONNECT:
		break;

	default:
		hexdump(SRM_DEBUG_PACKET_RX, NULL, "UNKNOWN", ctx->inbuf, len);
		break;
	}
}

static int srm_handle_fd(int fd, struct epoll_event *ev, void *arg)
{
	struct srm_epoll_ctx *ctx = arg;

	if (ev->events & EPOLLIN) {
		memset(ctx->inbuf, 0, EPOLL_BUF_SIZE);
		ctx->addrlen = sizeof(struct sockaddr_in);
		ssize_t len = recvfrom(fd, ctx->inbuf, EPOLL_BUF_SIZE,
				       0, (struct sockaddr *)&ctx->addr, &ctx->addrlen);
		if (len == -1 && errno != EAGAIN)
			return -1;
		if (len > 2) {
			ctx->inlen = len;
			handle_rx(ctx);
		}
	}

	if (ev->events & EPOLLERR) {
		srm_debug(SRM_DEBUG_ERROR, NULL, "error while reading srm fd\n");
		return -1;
	}
	return 0;
}

static struct srm_epoll_ctx *srm_create_epoll_ctx(GTree *clients, int fd)
{
	struct srm_epoll_ctx *ctx = g_new0(struct srm_epoll_ctx, 1);
	ctx->clients = clients;
	ctx->inbuf = g_malloc0(EPOLL_BUF_SIZE);
	ctx->outbuf = g_malloc0(EPOLL_BUF_SIZE);
	ctx->fd = fd;
	srm_debug(SRM_DEBUG_EPOLL, NULL, "%s: %p\n", __func__, ctx);
	return ctx;
}

static void srm_destroy_epoll_ctx(struct srm_epoll_ctx *ctx)
{
	g_free(ctx->inbuf);
	g_free(ctx->outbuf);
	g_free(ctx);
}

static int srm_create_socket(char *dev)
{
	struct sockaddr_in addr = { 0 };
	int fd, on = 1;

	fd = socket(AF_INET, SOCK_DGRAM, SOL_UDP);
	if (fd == -1) {
		srm_debug(SRM_DEBUG_ERROR, NULL, "failed to create socket: %m\n");
		return -1;
	}

	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(570);
	addr.sin_family = AF_INET;

	if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) == -1) {
		srm_debug(SRM_DEBUG_ERROR, NULL, "failed to set SO_BROADCAST: %m\n");
		close(fd);
		return -1;
	}

	if (dev && setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev)) == -1) {
		srm_debug(SRM_DEBUG_ERROR, NULL, "failed to set SO_BINDTODEVICE: %m\n");
		close(fd);
		return -1;
	}

	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
		srm_debug(SRM_DEBUG_ERROR, NULL, "failed to set O_NONBLOCK: %m\n");
		close(fd);
		return -1;
	}

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		srm_debug(SRM_DEBUG_ERROR, NULL, "failed to bind socket: %m\n");
		close(fd);
		return -1;
	}

	return fd;
}

int srm_init(GTree *clients)
{

	int fd;

	bcaddr.sin_family = AF_INET;
	bcaddr.sin_port = htons(570);
	bcaddr.sin_addr.s_addr = htonl(INADDR_BROADCAST);

	fd = srm_create_socket(config.interface);
	if (fd == -1)
		return -1;
	srmctx = srm_create_epoll_ctx(clients, fd);
	srmctx->fdctx = epoll_add(fd, EPOLLIN|EPOLLERR, srm_handle_fd, srmctx);
	if (!srmctx->fdctx) {
		srm_debug(SRM_DEBUG_ERROR, NULL, "%s: epoll_add: %m\n", __func__);
		return -1;
	}
	return 0;
}

void srm_exit(void)
{
	srm_destroy_epoll_ctx(srmctx);
}
