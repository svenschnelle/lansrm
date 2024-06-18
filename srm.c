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
#include <glib.h>
#include <stdarg.h>
#include <endian.h>
#include "lansrm.h"
#include "srm.h"


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
	for (GList *p = client->volumes; p; p = g_list_next(p)) {
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

	for (GList *p = client->volumes; p; p = g_list_next(p)) {
		struct srm_volume *volume = p->data;

		if (volume->index == index)
			return volume;
	}
	return NULL;
}

static int handle_srm_reset(struct srm_client *client)
{
	(void)client;
	// TODO: close files
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
	default:
		srm_debug(SRM_DEBUG_FILE, client, "%s: unhandled errno %d (%m)\n", __func__, errno);
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
	srm_debug(SRM_DEBUG_REQUEST, client, "%s: WRITE offset=%x, requested=%d, written=%zd acc=%d\n",
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

	srm_debug(SRM_DEBUG_REQUEST, client, "%s: POSITION id=%x offset=%x, whence=%d\n",
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

	srm_debug(SRM_DEBUG_REQUEST, client, "%s: READ file id=%x size=%d "
		  "actual=%zd offset=%x accesscode=%d, hdr_offset=%zx\n",
		  __func__, entry ? entry->client_fd : 0,
		  requested, len, offset, acc, entry->hdr_offset);
	return len != requested ? SRM_ERRNO_EOF_ENCOUNTERED : 0;
}

static int handle_srm_set_eof(struct srm_client *client,
			       void *request,
			      struct srm_return_empty *response,
			      int *responselen)
{
	(void)request;
	(void)response;
	(void)responselen;

	// TODO
	srm_debug(SRM_DEBUG_FILE, client, "%s: SET EOF\n", __func__);
	return SRM_ERRNO_SOFTWARE_BUG;
}

static int get_lif_info(int fd, uint32_t *out, uint32_t *bootaddr, off_t *hdr_offset)
{
	struct lif_header hdr;
	char buf[8];

	*hdr_offset = 0;

	if (read(fd, buf, sizeof(buf)) != sizeof(buf))
		return -1;

	if (!strncmp(buf+2, "HFSLIF", 6)) {
		if (lseek(fd, 0x100, SEEK_SET) == -1)
			return -1;
		*hdr_offset = 0x1e0;
	} else {
		if (lseek(fd, 0, SEEK_SET) == -1)
			return -1;
	}

	if (read(fd, &hdr, sizeof(hdr)) != sizeof(hdr))
		return -1;

	*hdr_offset += 0x20;
	*out = 0xffff0000 | be16toh(hdr.type);
	*bootaddr = ntohl(hdr.gp);
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

static int get_file_info(char *filename, struct srm_file_info *fi)

{
	srm_filetype_t filetype;
	uint32_t bootaddr = 0;
	uint32_t lif_type;
	struct stat stbuf;
	off_t hdr_offset;

	char *p;

	if (lstat(filename, &stbuf) == -1)
		return -1;

	fi->perm = htons(stbuf.st_mode & 0777);
	filetype = srm_map_filetype(stbuf.st_mode);
	switch (filetype) {
	case SRM_FILETYPE_DIRECTORY:
		fi->file_code = htonl(3);
		fi->record_mode = htonl(1);
		fi->record_mode = htonl(1);
		fi->share_code = htonl(1);
		fi->max_record_size = htonl(1);
		fi->logical_eof = htonl(1024);
		fi->physical_size = htonl(1);
		break;

	case SRM_FILETYPE_CHARDEV:
	case SRM_FILETYPE_BLOCKDEV:
	case SRM_FILETYPE_PIPEFIFO:
	case SRM_FILETYPE_REMOTE_PROCESS:
	case SRM_FILETYPE_UNKNOWN:
		fi->record_mode = 0;
		fi->file_code = htonl(0xffffe961);
		break;

	case SRM_FILETYPE_REG_FILE:
		fi->file_code = htonl(0xffffe94b);
		int fd = open(filename, O_RDONLY);
		if (fd == -1)
			return -1;
		if (get_lif_info(fd, &lif_type, &bootaddr, &hdr_offset) == -1)
			break;
		close(fd);
		fi->file_code = htonl(lif_type);
		fi->max_record_size = htonl(256);
		fi->logical_eof = htonl(srm_file_size(stbuf.st_size, hdr_offset));
		fi->physical_size = htonl(srm_file_size(stbuf.st_size, hdr_offset) / 256);
		break;
	}
	fi->max_file_size = htonl(-1);
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
	int error = SRM_ERRNO_NO_ERROR;

	entry = find_file_entry(client, id);
	if (!entry)
		return SRM_ERRNO_INVALID_FILE_ID;

	if (get_file_info(entry->filename->str, &response->fi))
		return errno_to_srm_error(client);

	response->fi.open_flag = htonl(1);
	response->fi.max_file_size = htonl(1024);
	response->fi.max_record_size = htonl(1);
	response->fi.share_code = -1;
	response->fi.capabilities = -1;

	srm_debug(SRM_DEBUG_REQUEST, client, "%s: FILEINFO id=%08x error=%d file=%s\n",
		  __func__, id, error, entry ? entry->filename->str : "");
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

	g_string_free(entry->filename, TRUE);
	close(entry->fd);
	g_tree_remove(client->files, &id);
	srm_debug(SRM_DEBUG_REQUEST, client, "%s: CLOSE %08x\n", __func__, id);
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

	srm_debug(SRM_DEBUG_REQUEST, client, "%s: present=%d, addr=%d, name='%s' driver='%s' cat='%s'\n", __func__,
		  present, addr, name, driver, cat);

	if (!present) {
		volume = get_volume_by_name(client, name);
		if (!volume) {
			srm_debug(SRM_DEBUG_FILE, client, "%s: failed to get volume %s\n", __func__, name);
			*error = SRM_ERRNO_VOLUME_NOT_FOUND;
			goto error;
		}
	} else {
		volume = get_volume_by_index(client, addr);
		if (!volume) {
			srm_debug(SRM_DEBUG_FILE, client, "%s: failed to get volume %d\n", __func__, addr);
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
				 struct srm_volume_header *vh,
				 struct srm_file_header *fh,
				 struct srm_file_name_set *names,
				 int start, int *error)
{
	struct srm_volume *volume;
	struct open_file_entry *entry;
	GString *ret, *filename;
	int wd = ntohl(fh->working_directory);

	ret = g_string_sized_new(128);//volume->path);
	if (wd) {
		entry = g_tree_lookup(client->files, &wd);
		if (!entry) {
			*error = SRM_ERRNO_INVALID_FILE_ID;
			return NULL;
		}
		g_string_append_printf(ret, "/%s", entry->filename->str);
	} else {
		volume = srm_volume_from_vh(client, vh, error);
		if (!volume)
			return NULL;
		g_string_append_printf(ret, "/%s", volume->path);
	}

	filename = srm_filename_from_fh(fh, names, start);
	if (filename->len)
		g_string_append_printf(ret, "/%s", filename->str);
	g_string_free(filename, TRUE);
	while(g_string_replace(ret, "//", "/", 0));
	return ret;
}

static int client_insert_file_entry(struct srm_client *client, GString *filename,
				    int fd, off_t hdr_offset)
{
	struct open_file_entry *entry = g_new0(struct open_file_entry, 1);
	int file_id;

	entry->filename = filename;
	entry->fd = fd;
	entry->hdr_offset = hdr_offset;

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
	struct stat stbuf = { 0 };
	uint32_t bootaddr = 0;
	int fd = -1, error = 0;
	uint32_t lif_type = 0;
	off_t hdr_offset = 0;
	GString *filename;
	srm_filetype_t filetype, opentype;

	opentype = ntohl(request->open_type);
	srm_debug(SRM_DEBUG_REQUEST, client, "%s: share_code %x, open_type: %x pad: %x %x %x\n", __func__,
		  ntohl(request->share_code), opentype,
		  ntohl(request->__pad0), ntohl(request->__pad1), ntohl(request->__pad2));
	filename = srm_get_filename(client, &request->vh,
				    &request->fh, request->filenames, 0, &errno);
	if (!filename) {
		error = SRM_ERRNO_FILE_PATHNAME_MISSING;
		goto error;
	}

	if (lstat(filename->str, &stbuf) == -1) {
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
		fd = open(filename->str, O_DIRECTORY);
		if (fd == -1) {
			error = errno_to_srm_error(client);
			break;
		}
		response->file_code = ntohl(3);
		response->record_mode = ntohl(1);
		response->max_record_size = ntohl(256);
		break;

	case SRM_FILETYPE_CHARDEV:
	case SRM_FILETYPE_BLOCKDEV:
	case SRM_FILETYPE_PIPEFIFO:
	case SRM_FILETYPE_REG_FILE:
		response->file_code = htonl(0xffffe94b);
		switch (ntohs(request->open_type)) {
		case SRM_OPENTYPE_RDWR:
			fd = open(filename->str, O_RDWR);
			if (fd != -1)
				break;
			/* fallthrough */
		case SRM_OPENTYPE_RDONLY:
			fd = open(filename->str, O_RDONLY);
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

		get_lif_info(fd, &lif_type, &bootaddr, &hdr_offset);
		if (lseek(fd, stbuf.st_size, SEEK_SET) == -1) {
			error = errno_to_srm_error(client);
			break;
		}

		response->file_code = htonl(lif_type);
		response->open_logical_eof = htonl(stbuf.st_size > hdr_offset ? (stbuf.st_size - hdr_offset) : 0);
		response->boot_start_address = htonl(bootaddr);
		response->max_file_size = htonl(INT_MAX);
		response->max_record_size = htonl(256);
		break;

	case SRM_FILETYPE_UNKNOWN:
	case SRM_FILETYPE_REMOTE_PROCESS:
		error = SRM_ERRNO_FILE_NOT_FOUND;
		break;
		response->record_mode = 0;
		response->file_code = htonl(0xffffe94b);
		break;
	}
	response->open_logical_eof = htonl(stbuf.st_size - hdr_offset);
	response->sec_ext_size = htonl(stbuf.st_size - hdr_offset);
	response->file_id = htonl(client_insert_file_entry(client, filename, fd, hdr_offset));
error:
	srm_debug(SRM_DEBUG_REQUEST, client, "%s: OPEN file='%s' fd=%d id=%08x hdrsz=%ld error=%d\n",
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
	struct dirent *dirent = NULL;
	GString *filename = NULL;
	int start, max, cnt = 0;
	GList *names = NULL;
	int error = SRM_ERRNO_NO_ERROR;
	srm_filetype_t filetype;
	struct stat stbuf;
	DIR *dir;

	max = ntohl(request->max_num_files);
	start = ntohl(request->file_index);

	filename = srm_get_filename(client, &request->vh, &request->fh,
				   request->filenames, 0, &error);
	if (!filename)
		goto error;

	if (lstat(filename->str, &stbuf) == -1) {
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
			if (!get_file_info(fullname->str, &response->fi[cnt]))
				cnt++;
			g_string_free(fullname, TRUE);
		}
		g_list_free_full(names, free);
		response->num_files = htonl(cnt);
		break;
	case SRM_FILETYPE_REG_FILE:
		if (get_file_info(filename->str, &response->fi[0]) == -1) {
			error = SRM_ERRNO_VOLUME_IO_ERROR;
			break;
		}
		response->num_files = htonl(1);
		break;
	case SRM_FILETYPE_BLOCKDEV:
	case SRM_FILETYPE_CHARDEV:
	case SRM_FILETYPE_PIPEFIFO:
	case SRM_FILETYPE_UNKNOWN:
	case SRM_FILETYPE_REMOTE_PROCESS:
		response->fi[0].file_code = htonl(0xffffe961);
		response->fi[0].record_mode = 0;
		response->num_files = htonl(1);
		break;
	}
error:
	srm_debug(SRM_DEBUG_REQUEST, client, "%s: CAT '%s' start=%d max=%d wd=%x results=%d error=%d\n",
		  __func__, filename ? filename->str : "", start, max, ntohl(request->fh.working_directory),
		  cnt, error);
	if (filename)
		g_string_free(filename, TRUE);
	*responselen = sizeof(*response);
	return error;
}

static int handle_srm_createfile(struct srm_client *client,
				 struct srm_create_file *request)
{
	int fd, type, error = 0;
	GString *filename;

	type = ntohl(request->file_code);
	filename = srm_get_filename(client, &request->vh, &request->fh,
				    request->filenames, 0, &error);
	if (!filename)
		return SRM_ERRNO_FILE_PATHNAME_MISSING;
	if (type == 3) {
		if (mkdir(filename->str, 0755) == -1)
			error = errno_to_srm_error(client);
	} else {
		fd = open(filename->str, O_WRONLY|O_TRUNC|O_CREAT, 0644);
		if (fd == -1) {
			error = errno_to_srm_error(client);
			goto error;
		}
		struct lif_header buf = { 0 };
		memcpy(buf.name, "WS_FILE   ", 10);
		buf.type = htobe16(type & 0xffff);
		buf.gp = htole32(request->boot_start_address);
		if (write(fd, &buf, sizeof(buf)) == -1 || close(fd) == -1)
			error = errno_to_srm_error(client);
	}
error:
	srm_debug(SRM_DEBUG_REQUEST, client, "%s: CREATE FILE: filename='%s' %08x\n", __func__, filename->str, type);
	g_string_free(filename, TRUE);
	return error;
}

static int handle_srm_create_link(struct srm_client *client,
				  struct srm_create_link *request)
{
	GString *old_filename = NULL, *new_filename = NULL;
	int error, purge, err;

	purge = ntohl(request->purge_old_link);

	old_filename = srm_get_filename(client,&request->vh, &request->fh_old,
					request->filenames,
					0, &error);
	if (!old_filename)
		goto error;

	new_filename = srm_get_filename(client, &request->vh, &request->fh_new,
					request->filenames,
					ntohl(request->fh_old.file_name_sets), &error);
	if (!new_filename)
		goto error;

	if (purge)
		err = rename(old_filename->str, new_filename->str);
	else
		err = link(old_filename->str, new_filename->str);

	error = err ? errno_to_srm_error(client) : 0;
error:
	srm_debug(SRM_DEBUG_REQUEST, client, "%s: CREATELINK %s -> %s, purge %d, error %d\n", __func__,
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
	srm_debug(SRM_DEBUG_REQUEST, client, "%s: VOLSTATUS vname='%s' error=%d\n",
		  __func__, volume ? volume->name : "", error);
	return error;
}

static int handle_srm_purgelink(struct srm_client *client,
				struct srm_purge_link *request)
{
	GString *filename;
	int error = SRM_ERRNO_NO_ERROR;

	filename = srm_get_filename(client, &request->vh,
				    &request->fh,
				    request->filenames, 0, &error);
	if (!filename)
		goto error;

	if (unlink(filename->str) == -1)
		error = errno_to_srm_error(client);
error:
	srm_debug(SRM_DEBUG_REQUEST, client, "%s: PURGE LINK %s error=%d\n",
		  __func__,filename->str, error);
	g_string_free(filename, TRUE);
	return error;
}

static int handle_srm_change_protect(struct srm_client *client)
{

	srm_debug(SRM_DEBUG_REQUEST, client, "%s: CHANGE PROTECT\n", __func__);
	return SRM_ERRNO_VOLUME_IO_ERROR;
}

static int handle_srm_xchg_open(struct srm_client *client,
				struct srm_xchg_open *request)
{
	struct open_file_entry *entry1, *entry2;
	uint32_t id1 = ntohl(request->file_id1);
	uint32_t id2 = ntohl(request->file_id2);
	GString *tmpname = NULL;

	entry1 = find_file_entry(client, id1);
	if (!entry1)
		return SRM_ERRNO_INVALID_FILE_ID;

	entry2 = find_file_entry(client, id2);
	if (!entry2)
		return SRM_ERRNO_INVALID_FILE_ID;

	g_string_printf(tmpname, "%s.TMP", entry2->filename->str);
	if (rename(entry1->filename->str, tmpname->str) == -1)
		return errno_to_srm_error(client);

	if (rename(entry2->filename->str, entry1->filename->str) == -1) {
		rename(tmpname->str, entry1->filename->str);
		return errno_to_srm_error(client);
	}

	if (rename(tmpname->str, entry2->filename->str) == -1) {
		rename(entry1->filename->str, entry2->filename->str);
		rename(tmpname->str, entry1->filename->str);
		return errno_to_srm_error(client);
	}

	srm_debug(SRM_DEBUG_REQUEST, client, "XCHG OPEN: id1=%x name1='%s' id2=%x name2='%s'\n",
		  id1, entry1 ? entry1->filename->str : "", id2, entry2 ? entry2->filename->str : "");
	if (tmpname)
		g_string_free(tmpname, TRUE);
	return 0;
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
		ret = handle_srm_set_eof(client, (void *)request->payload,
					 (void *)(void *)response->payload, &responselen);
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
		srm_debug(SRM_DEBUG_REQUEST, client, "%s: unknown request %d\n",
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
	srm_debug(SRM_DEBUG_RESPONSE, client, "%s = %s (%d), sequence = %x\n",
		  srm_request_to_name(type), srm_strerror(ret), ret, ntohl(request->hdr.user_sequencing_field));
	return responselen;
}
