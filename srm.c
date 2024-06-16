#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <glib.h>
#include <stdarg.h>
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
	for (GList *p = client->volumes; p; p = g_list_next(p)) {
		struct srm_volume *volume = p->data;

		if (volume->index == index)
			return volume;
	}
	return NULL;
}

static void srm_send_response(struct srm_client *client, void *request, void *response,
			      int len, int level, int srm_errno)
{
	struct srm_return_header *hdr = (struct srm_return_header *)response;
	struct srm_send_header *p = (struct srm_send_header *)request;

	hdr->level = level;
	hdr->message_length = htonl(len - 4);
	hdr->return_request_type = htonl(-htonl(p->request_type));
	hdr->user_sequencing_field = p->user_sequencing_field;
	hdr->status = htonl(srm_errno);

	srm_debug(SRM_DEBUG_RESPONSE, client, "%s: length %d, request type %x, sequence %d status %d\n",
		__func__, ntohl(hdr->message_length), ntohl(hdr->return_request_type),
		  ntohl(hdr->user_sequencing_field), srm_errno);

	lansrm_send(client, response, len);
}

static void handle_srm_reset(struct srm_client *client, void *buf)
{
	struct srm_return_empty ret = { 0 };
	srm_send_response(client, buf, &ret, sizeof(ret), 2, 0x01000000);
}

static void handle_srm_areyoualive(struct srm_client *client, void *buf)
{
	struct srm_return_empty ret = { 0 };
	srm_send_response(client, buf, &ret, sizeof(ret), 2, 0x01000000);
}

static int errno_to_srm_error(struct srm_client *client)
{
	switch(errno) {
	case 0:
		return 0;
	case ENOENT:
		return SRM_ERRNO_FILE_NOT_FOUND;
	case EPERM:
	case EACCES:
		return SRM_ERRNO_ACCESS_TO_FILE_NOT_ALLOWED;
	case EISDIR:
		return 0;
	case EIO:
		return SRM_ERRNO_VOLUME_IO_ERROR;
	default:
		srm_debug(SRM_DEBUG_FILE, client, "%s: unhandled errno %d (%m)\n", __func__);
		return SRM_ERRNO_SOFTWARE_BUG;
	}
}

static struct open_file_entry *find_file_entry(struct srm_client *client, int fd)
{
	return g_tree_lookup(client->files, &fd);
}

static void handle_srm_write(struct srm_client *client, struct srm_write *req)
{
	struct srm_return_write ret = { 0 };
	uint32_t offset,requested, id, acc;
	struct open_file_entry *entry;
	int error = 0;
	ssize_t len = 0;

	requested = ntohl(req->requested);
	id = ntohl(req->file_id);
	acc = ntohl(req->access_code);
	offset = ntohl(req->offset);

	entry = find_file_entry(client, id);
	if (!entry)
		goto error;

	if ((acc == 0 && lseek(entry->fd, offset + entry->hdr_offset, SEEK_SET) == -1)) {
		error = errno_to_srm_error(client);
		goto error;
	}

	len = write(entry->fd, req->data, requested);
	if (len == -1) {
		error = errno_to_srm_error(client);
		goto error;
	}

	ret.actual = htonl(len);
error:
	srm_debug(SRM_DEBUG_REQUEST, client, "%s: WRITE offset=%x, requested=%d, written=%zd acc=%d\n",
		  __func__, offset, requested, len, acc);
	srm_send_response(client, req, &ret, sizeof(ret), 7, error);
}

static void handle_srm_position(struct srm_client *client, struct srm_position *req)
{
	struct srm_return_empty ret = { 0 };
	struct open_file_entry *entry;
	uint32_t id, offset;
	uint8_t whence;
	int error = 0;

	offset = ntohl(req->offset);
	whence = req->position_type ? SEEK_CUR : SEEK_SET;
	id = ntohl(req->file_id);

	entry = find_file_entry(client, id);
	if (!entry) {
		error = SRM_ERRNO_INVALID_FILE_ID;
		goto error;
	}

	if (whence == SEEK_SET)
		offset += entry->hdr_offset;

	if (lseek(entry->fd, offset, whence) == -1)
		error = errno_to_srm_error(client);
error:
	srm_debug(SRM_DEBUG_REQUEST, client, "%s: POSITION id=%x offset=%x, whence=%d, error=%zd\n",
		  __func__, entry ? entry->client_fd : 0, offset, whence, error);
	srm_send_response(client, req, &ret, sizeof(ret), 7, error);
}

static void handle_srm_read(struct srm_client *client, struct srm_read *req)
{
	uint32_t requested, offset, id, acc;
	struct srm_return_read ret = { 0 };
	struct open_file_entry *entry;
	int retlen = 0, error = 0;
	ssize_t len = 0;

	requested = ntohl(req->requested);
	offset = ntohl(req->offset);
	id = ntohl(req->file_id);
	acc = ntohl(req->access_code);

	entry = find_file_entry(client, id);
	if (!entry) {
		error = SRM_ERRNO_INVALID_FILE_ID;
		goto error;
	}

	if (acc == 0 && lseek(entry->fd, offset + entry->hdr_offset, SEEK_SET) == -1) {
		error = errno_to_srm_error(client);
		goto error;
	}

	if (requested > 512)
		requested = 512;

	len = read(entry->fd, ret.data, requested);
	if (len == -1) {
		ret.hdr.status = htonl(errno_to_srm_error(client));
		len = 0;
	}

	if (len > 0)
		ret.actual = htonl(len);

	retlen = sizeof(ret) - 512 + len;
	if (len != requested)
		error = SRM_ERRNO_EOF_ENCOUNTERED;
error:
	srm_debug(SRM_DEBUG_REQUEST, client, "%s: READ file id=%x size=%d "
		  "actual=%zd offset=%x accesscode=%d, hdr_offset=%zx error=%zd\n",
		  __func__, entry ? entry->client_fd : 0,
		  requested, len, offset, acc, entry->hdr_offset, error);
	srm_send_response(client, req, &ret, retlen, 7, error);
}

static void handle_srm_set_eof(struct srm_client *client, struct srm_file_info *req)
{
	struct srm_return_empty ret = { 0 };

	// TODO
	srm_debug(SRM_DEBUG_FILE, client, "%s: SET EOF\n", __func__);
	srm_send_response(client, req, &ret, sizeof(ret), 7, 0);
}

static int get_lif_info(int fd, uint16_t *out, uint32_t *bootaddr, off_t *hdr_offset)
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
	*out = ntohs(hdr.type);
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

static int get_file_info(char *filename, struct srm_file_info *fi)

{
	uint16_t lif_type = 0xffff;
	uint32_t bootaddr = 0;
	struct stat stbuf;
	off_t hdr_offset;
	char *p;

	if (lstat(filename, &stbuf) == -1)
		return -1;

	fi->perm = htons(stbuf.st_mode & 0777);

	if (S_ISREG(stbuf.st_mode)) {
		int fd = open(filename, O_RDONLY);
		if (fd == -1)
			return -1;
		get_lif_info(fd, &lif_type, &bootaddr, &hdr_offset);
		close(fd);
		fi->max_record_size = htonl(256);
		fi->logical_eof = htonl(srm_file_size(stbuf.st_size, hdr_offset));
		fi->physical_size = htonl(srm_file_size(stbuf.st_size, hdr_offset) / 256);
	} else if (S_ISDIR(stbuf.st_mode)) {
		lif_type = 0xff03;
		fi->record_mode = htonl(1);
		fi->share_code = htonl(1);
		fi->max_record_size = htonl(1);
		fi->logical_eof = htonl(1024);
		fi->physical_size = htonl(1);
	} else {
		return -1;
	}

	fi->file_code = htonl(0xffff0000 | lif_type);
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

static void handle_srm_fileinfo(struct srm_client *client, struct srm_fileinfo *req)
{
	struct srm_return_fileinfo ret = { 0 };
	struct open_file_entry *entry;
	int id = ntohl(req->file_id);
	int error = 0;

	entry = find_file_entry(client, id);
	if (!entry) {
		error = SRM_ERRNO_INVALID_FILE_ID;
		goto error;
	}

	if (get_file_info(entry->filename->str, &ret.fi)) {
		error = errno_to_srm_error(client);
		goto error;
	}

	ret.fi.open_flag = htonl(1);
	ret.fi.max_file_size = htonl(1024);
	ret.fi.max_record_size = htonl(1);
	ret.fi.share_code = -1;
	ret.fi.capabilities = -1;
error:
	srm_debug(SRM_DEBUG_REQUEST, client, "%s: FILEINFO id=%08x error=%d file=%s\n",
		  __func__, id, error, entry ? entry->filename->str : "");
	srm_send_response(client, req, &ret, sizeof(ret), 7 ,error);
}

static void handle_srm_close(struct srm_client *client, struct srm_close *req)
{
	int id = ntohl(req->file_id);
	struct srm_return_empty ret = { 0 };
	struct open_file_entry *entry;
	int error = 0;

	entry = find_file_entry(client, id);
	if (!entry) {
		error = SRM_ERRNO_INVALID_FILE_ID;
		goto error;
	}

	g_string_free(entry->filename, TRUE);
	close(entry->fd);
	g_tree_remove(client->files, &id);
error:
	srm_debug(SRM_DEBUG_REQUEST, client, "%s: CLOSE %08x error=%d\n", __func__, id, error);
	srm_send_response(client, req, &ret, sizeof(ret), 7, error);
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
	struct open_file_entry *entry = NULL;
	struct srm_volume *volume;
	int addr, present;
	char *driver, *name, *cat;

	present = ntohl(vh->device_address_present);
	addr = ntohl(vh->device_address.address1);
	driver = srm_to_c_string(vh->driver_name);
	cat = srm_to_c_string(vh->catalogue_organization);
	name = srm_to_c_string(vh->volume_name);

	srm_debug(SRM_DEBUG_REQUEST, client, "%s: present=%d, addr=%d, name='%s' driver='%s' cat='%s' %s\n", __func__,
		  present, addr, name, driver, cat, entry ? entry->filename->str : "");

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
	} while(g_tree_lookup(client->files, &file_id));

	entry->client_fd = file_id;

	g_tree_insert(client->files, &entry->client_fd, entry);
	return file_id;
}

static void handle_srm_open(struct srm_client *client, struct srm_file_open *req)
{
	struct srm_return_file_open ret = { 0 };
	struct stat stbuf = { 0 };
	uint32_t bootaddr = 0;
	int fd = -1, error = 0;
	uint16_t lif_type = 0;
	off_t hdr_offset = 0;
	GString *filename;

	filename = srm_get_filename(client, &req->vh, &req->fh, req->filenames, 0, &errno);
	if (!filename)
		goto error;

	fd = open(filename->str, O_RDWR);
	if (fd == -1 && errno == EISDIR) {
		fd = open(filename->str, O_DIRECTORY);
		if (fd != -1) {
			ret.file_code = ntohl(0xffffff03);
			ret.record_mode = ntohl(1);
			ret.max_file_size = ntohl(1024);
			ret.max_record_size = ntohl(1);
			ret.sec_ext_size = 128;
			ret.open_logical_eof = ntohl(1024);
			ret.share_bits = -1;
			goto insert;
		}
	}

	if (fd == -1) {
		error = errno_to_srm_error(client);
		goto error;
	}

	if (fstat(fd, &stbuf) == -1) {
		error = errno_to_srm_error(client);
		goto error;
	}

	get_lif_info(fd, &lif_type, &bootaddr, &hdr_offset);
	if (lseek(fd, hdr_offset, SEEK_SET) == -1) {
		errno = errno_to_srm_error(client);
		goto error;
	}

	ret.file_code = htonl(0xffff0000 | lif_type);
	ret.open_logical_eof = htonl(stbuf.st_size > hdr_offset ? (stbuf.st_size - hdr_offset) : 0);
	ret.boot_start_address = htonl(bootaddr);
	ret.max_file_size = htonl(INT_MAX);
	ret.max_record_size = htonl(256);
	ret.share_bits = htonl(0xfffffff);
insert:
	ret.file_id = htonl(client_insert_file_entry(client, filename, fd, hdr_offset));
error:
	srm_debug(SRM_DEBUG_REQUEST, client, "%s: OPEN file='%s' fd=%d id=%08x hdrsz=%s error=%d\n",
		  __func__, filename ? filename->str : "", fd, ntohl(ret.file_id), hdr_offset, error);
	if (filename && error)
		g_string_free(filename, TRUE);
	srm_send_response(client, req, &ret, sizeof(ret), 7, error);
}

static int srm_dir_compare(const void *a, const void *b)
{
	return strcmp(a, b);
}

static void handle_srm_catalog(struct srm_client *client, struct srm_catalog *req)
{
	struct srm_return_catalog ret = { 0 };
	int start, max, cnt = 0;
	struct dirent *dirent = NULL;
	GString *dirname = NULL;
	GList *names = NULL;
	int error = 0;
	DIR *dir;

	max = ntohl(req->max_num_files);
	start = ntohl(req->file_index);

	dirname = srm_get_filename(client, &req->vh, &req->fh, req->filenames, 0, &error);
	if (!dirname)
		goto error;

	dir = opendir(dirname->str);
	if (!dir) {
		error = errno_to_srm_error(client);
		goto error;
	}

	while ((dirent = readdir(dir)))
		names = g_list_insert_sorted(names, g_strdup(dirent->d_name), srm_dir_compare);

	closedir(dir);

	if (start < 1)
		start = 1;

	GList *p = g_list_nth(names, start - 1);
	for (cnt = 0;  p && cnt < max; p = g_list_next(p)) {
		GString *fullname = g_string_new(dirname->str);
		g_string_append_printf(fullname, "/%s", (char *)p->data);
		if (!get_file_info(fullname->str, &ret.fi[cnt]))
			cnt++;
		g_string_free(fullname, TRUE);

	}
	g_list_free_full(names, free);
	ret.num_files = htonl(cnt);
error:
	srm_debug(SRM_DEBUG_REQUEST, client, "%s: CAT '%s' start=%d max=%d wd=%x results=%d error=%d\n",
		  __func__, dirname ? dirname->str : "", start, max, ntohl(req->fh.working_directory), cnt, error);
	if (dirname)
		g_string_free(dirname, TRUE);
	srm_send_response(client, req, &ret, sizeof(ret), 7, error);
}

static void handle_srm_createfile(struct srm_client *client, struct srm_create_file *req)
{
	struct srm_return_empty ret = { 0 };
	int fd, type, error = 0;
	GString *filename;

	type = ntohl(req->file_code) & 0xffff;
	filename = srm_get_filename(client, &req->vh, &req->fh, req->filenames, 0, &error);
	if (!filename)
		goto error;
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
		buf.type = req->file_code >> 16;
		buf.gp = req->boot_start_address;
		if (write(fd, &buf, sizeof(buf)) == -1 || close(fd) == -1)
			error = errno_to_srm_error(client);
	}
error:
	srm_debug(SRM_DEBUG_FILE, client, "%s: CREATE FILE: %s %08x\n", __func__, filename, type);
	g_string_free(filename, TRUE);
	srm_send_response(client, req, &ret, sizeof(ret), 7, error);
}

static void handle_srm_create_link(struct srm_client *client, struct srm_create_link *req)
{
	GString *old_filename = NULL, *new_filename = NULL;
	struct srm_return_empty ret = { 0 };
	int error, purge, err;

	purge = ntohl(req->purge_old_link);

	old_filename = srm_get_filename(client,&req->vh, &req->fh_old, req->filenames,
					0, &error);
	if (!old_filename)
		goto error;

	new_filename = srm_get_filename(client, &req->vh, &req->fh_new, req->filenames,
					ntohl(req->fh_old.file_name_sets), &error);
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
	srm_send_response(client, req, &ret, sizeof(ret), 7, error);
}

static void handle_srm_volstatus(struct srm_client *client, struct srm_volume_status *req)
{
	struct srm_return_volume_status ret = { 0 };
	struct srm_volume *volume;
	int error = 0;

	volume = srm_volume_from_vh(client, &req->vh, &error);
	if (volume) {
		c_string_to_srm(ret.volname, volume->name);
		ret.exist = 1;
		ret.srmux = 1;
	}
	srm_debug(SRM_DEBUG_REQUEST, client, "%s: VOLSTATUS vname='%s' error=%d\n",
		  __func__, volume ? volume->name : "", error);
	srm_send_response(client, req, &ret, sizeof(ret), 7, error);
}

static void handle_srm_purgelink(struct srm_client *client, struct srm_purge_link *req)
{
	struct srm_return_empty ret = { 0 };
	GString *filename;
	int error = 0;

	filename = srm_get_filename(client, &req->vh, &req->fh, req->filenames, 0, &error);
	if (!filename)
		goto error;

	if (unlink(filename->str) == -1)
		error = errno_to_srm_error(client);
error:
	srm_debug(SRM_DEBUG_REQUEST, client, "%s: PURGE LINK %s error=%d\n",
		  __func__,filename->str, error);
	g_string_free(filename, TRUE);
	srm_send_response(client, req, &ret, sizeof(ret), 7, error);
}

static void handle_srm_change_protect(struct srm_client *client, struct srm_fileinfo *req)
{
	struct srm_return_empty ret = { 0 };

	srm_debug(SRM_DEBUG_REQUEST, client, "%s: CHANGE PROTECT\n", __func__);
	srm_send_response(client, req, &ret, sizeof(ret), 7, 0);
}

static void handle_srm_xchg_open(struct srm_client *client, struct srm_xchg_open *req)
{
	struct open_file_entry *entry1, *entry2;
	struct srm_return_header ret = { 0 };
	uint32_t id1 = ntohl(req->file_id1);
	uint32_t id2 = ntohl(req->file_id2);
	GString *tmpname = NULL;
	int error = 0;

	entry1 = find_file_entry(client, id1);
	if (!entry1) {
		error = SRM_ERRNO_INVALID_FILE_ID;
		goto error;
	}

	entry2 = find_file_entry(client, id2);
	if (!entry2) {
		error = SRM_ERRNO_INVALID_FILE_ID;
		goto error;
	}

	g_string_printf(tmpname, "%s.TMP", entry2->filename->str);
	if (rename(entry1->filename->str, tmpname->str) == -1) {
		error = errno_to_srm_error(client);
		goto error;
	}

	if (rename(entry2->filename->str, entry1->filename->str) == -1) {
		rename(tmpname->str, entry1->filename->str);
		error = errno_to_srm_error(client);
		goto error;
	}


	if (rename(tmpname->str, entry2->filename->str) == -1) {
		rename(entry1->filename->str, entry2->filename->str);
		rename(tmpname->str, entry1->filename->str);
		error = errno_to_srm_error(client);
		goto error;
	}
error:
	srm_debug(SRM_DEBUG_REQUEST, client, "XCHG OPEN: id1=%x name1='%s' id2=%x name2='%s' error=%d\n",
		  id1, entry1 ? entry1->filename->str : "", id2, entry2 ? entry2->filename->str : "", error);
	if (tmpname)
		g_string_free(tmpname, TRUE);
	srm_send_response(client, req, &ret, sizeof(ret), 7, error);
}

void srm_handle_request(struct srm_client *client, void *buf, size_t len)
{
	struct srm_send_header *hdr = (struct srm_send_header *)buf;
	size_t length;

	if (len < sizeof(struct srm_send_header)) {
		srm_debug(SRM_DEBUG_FILE, client, "%s: len %zd < sizeof(struct srm_send_header)\n",
			__func__, len);
		return;
	}

	length = ntohl(hdr->message_length) + 4;

	if (len  < length) {
		srm_debug(SRM_DEBUG_FILE, client, "%s: len %zd < message_length %zd\n",
			__func__, len, length);
		return;
	}

	switch(ntohl(hdr->request_type)) {
	case SRM_REQ_RESET:
		handle_srm_reset(client, buf);
		break;

	case SRM_REQ_AREYOUALIVE:
		handle_srm_areyoualive(client, buf);
		break;

	case SRM_REQ_WRITE:
		handle_srm_write(client, buf);
		break;

	case SRM_REQ_POSITION:
		handle_srm_position(client, buf);
		break;

	case SRM_REQ_READ:
		handle_srm_read(client, buf);
		break;

	case SRM_REQ_SET_EOF:
		handle_srm_set_eof(client, buf);
		break;

	case SRM_REQ_FILEINFO:
		handle_srm_fileinfo(client, buf);
		break;

	case SRM_REQ_CLOSE:
		handle_srm_close(client, buf);
		break;

	case SRM_REQ_OPEN:
		handle_srm_open(client, buf);
		break;

	case SRM_REQ_CATALOG:
		handle_srm_catalog(client, buf);
		break;

	case SRM_REQ_CREATEFILE:
		handle_srm_createfile(client, buf);
		break;

	case SRM_REQ_CREATELINK:
		handle_srm_create_link(client, buf);
		break;

	case SRM_REQ_VOLSTATUS:
		handle_srm_volstatus(client, buf);
		break;

	case SRM_PURGE_LINK:
		handle_srm_purgelink(client, buf);
		break;

	case SRM_REQ_CHANGE_PROTECT:
		handle_srm_change_protect(client, buf);
		break;

	case SRM_REQ_XCHG_OPEN:
		handle_srm_xchg_open(client, buf);
		break;

	default:
		srm_debug(SRM_DEBUG_REQUEST, client, "%s: unknown request %d, level %d, len %zd\n",
			__func__, ntohl(hdr->request_type), hdr->level, length);
		break;
	}
}

