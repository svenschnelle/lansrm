#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <arpa/inet.h>
#include <glib.h>

#include "lansrm.h"
#include "config.h"
#include "debug.h"

struct config config;

struct client_config *get_client_config(struct sockaddr_in *addr)
{
	for (GList *p = config.configs; p; p = g_list_next(p)) {
		struct client_config *c = p->data;
		if (!memcmp(&c->addr.sin_addr.s_addr, &addr->sin_addr.s_addr,
			    sizeof(addr->sin_addr.s_addr)))
			return c;
	}
	return NULL;
}

struct client_config *get_client_config_hwaddr(uint8_t *hwaddr)
{
	struct sockaddr_in clientaddr;
	char hwaddr_string[32];
	int ret;

	snprintf(hwaddr_string, sizeof(hwaddr_string)-1, "%02x:%02x:%02x:%02x:%02x:%02x",
		 hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
	char *tmp = g_key_file_get_string(config.keyfile, "global", hwaddr_string, NULL);
	if (!tmp) {
		srm_debug(SRM_DEBUG_CONNECT, NULL, "unknown client %s\n", hwaddr_string);
		return NULL;
	}
	ret = inet_pton(AF_INET, tmp, &clientaddr.sin_addr);
	if (ret != 1) {
		srm_debug(SRM_DEBUG_FILE, hwaddr_string, "Failed to parse IP %s\n", tmp);
		g_free(tmp);
			return NULL;
	}
	g_free(tmp);
	return get_client_config(&clientaddr);
}

static void volume_free(struct srm_volume *volume)
{
	g_free(volume->fullpath);
	g_free(volume->path);
	g_free(volume->name);
	if (volume->dir)
		closedir(volume->dir);
	g_free(volume);
}

static void client_config_free(struct client_config *client)
{
	for (GList *p = client->volumes; p; p = g_list_next(p))
		volume_free(p->data);
	g_list_free(client->volumes);
	g_strfreev(client->bootfiles);
	g_free(client->bootpath);
	g_free(client);
}

struct srm_volume *volume_by_name(struct client_config *client, const char *name)
{
	for (GList *p = client->volumes; p; p = g_list_next(p)) {
		struct srm_volume *volume = p->data;
		if (!strcmp(volume->name, name))
			return volume;
	}
	return NULL;
}

static struct srm_volume *read_volume(char *name, char *chrootpath)
{
	char *uid, *gid, *umask, *endp;
	struct srm_volume *ret;
	GError *gerr = NULL;
	struct passwd *pwd;
	struct group *grp;
	int  index;

	ret = g_new0(struct srm_volume, 1);

	index = g_key_file_get_integer(config.keyfile, name, "volume", &gerr);
	if (gerr) {
		srm_debug(SRM_DEBUG_ERROR, NULL, "failed to fetch index for volume %s: %s\n",
			  name, gerr->message);
		goto error;
	}

	ret->path = g_key_file_get_string(config.keyfile, name, "path", &gerr);
	if (!ret->path) {
		srm_debug(SRM_DEBUG_ERROR, NULL, "failed to fetch path for volume %s: %s\n",
			  name, gerr->message);
		goto error;
	}

	GString *fullpath = g_string_sized_new(128);
	g_string_printf(fullpath, "%s/%s", chrootpath ? chrootpath : "", ret->path);
	ret->fullpath = g_string_free(fullpath, FALSE);

	ret->dir = opendir(ret->fullpath);
	if (!ret->dir) {
		srm_debug(SRM_DEBUG_ERROR, NULL, "opendir %s failed while adding volume %s: %m\n", ret->path, name);
		goto error;
	}


	ret->umask = 022;

	ret->dirfd = dirfd(ret->dir);
	if (ret->dirfd == -1) {
		srm_debug(SRM_DEBUG_ERROR, NULL, "dirfd failed while adding volume %s: %m\n", name);
		goto error;
	}

	uid = g_key_file_get_string(config.keyfile, name, "uid", NULL);
	if (uid) {
		pwd = getpwnam(uid);
		if (pwd) {
			ret->uid = pwd->pw_uid;
			g_free(uid);
		} else {
			srm_debug(SRM_DEBUG_ERROR, NULL, "failed to resolve uid '%s', "
				  "ignoring volume '%s'\n", uid, name);
			g_free(uid);
			goto error;
		}
	}

	gid = g_key_file_get_string(config.keyfile, name, "gid", NULL);
	if (gid) {
		grp = getgrnam(gid);
		if (grp) {
			ret->gid = grp->gr_gid;
			g_free(gid);
		} else {
			srm_debug(SRM_DEBUG_ERROR, NULL, "failed to resolve gid '%s', "
				  "ignoring volume '%s'\n",
				  gid, name);
			g_free(gid);
			goto error;
		}
	}

	umask = g_key_file_get_string(config.keyfile, name, "umask", &gerr);
	if (umask) {
		ret->umask = strtoul(umask, &endp, 8);
		if (*endp) {
			srm_debug(SRM_DEBUG_ERROR, NULL, "failed to parse umask '%s' at '%s' in volume '%s' configuration\n",
				  umask, endp, name);
			g_free(umask);
			goto error;
		}
		g_free(umask);
	} else {
		g_error_free(gerr);
	}
	ret->name = g_strdup(name);
	ret->index = index;
	return ret;
error:
	if (gerr)
		g_error_free(gerr);
	volume_free(ret);
	return NULL;
}

static GList *read_volumes(const char *name)
{
	const gchar *keys[] = { name, "global" };
	struct srm_volume *vol;
	GList *ret = NULL;
	unsigned int i, j;
	gchar **volumes;
	gsize volcount;

	for (i = 0; i < ARRAY_SIZE(keys); i++) {
		volumes = g_key_file_get_string_list(config.keyfile, keys[i],
						     "volumes", &volcount, NULL);
		if (!volumes)
			continue;
		for(j = 0; j < volcount; j++) {
			vol = read_volume(volumes[j], config.chroot);
			if (!vol)
				continue;
			srm_debug(SRM_DEBUG_CONNECT, NULL, "adding %s volume %d: "
				  "name='%s' path='%s' uid=%u gid=%u for client '%s'\n",
				  i ? "global" : "local", vol->index, vol->name, vol->fullpath,
				  vol->uid, vol->gid, name);
			ret = g_list_append(ret, vol);
		}
		g_strfreev(volumes);
	}
	return ret;
}

static struct client_config *parse_client_config(const char *name)
{
	struct client_config *ret = g_new(struct client_config, 1);

	ret->bootfilefd = -1;
	ret->volumes = read_volumes(name);
	ret->node = g_key_file_get_integer(config.keyfile, name, "node", NULL);
	ret->hostnode = g_key_file_get_integer(config.keyfile, name, "hostnode", NULL);
	ret->bootfiles = g_key_file_get_string_list(config.keyfile, name, "bootfiles", NULL, NULL);
	ret->bootpath = g_key_file_get_string(config.keyfile, name, "bootpath", NULL);
	ret->tempdir = g_key_file_get_string(config.keyfile, name, "tempdir", NULL);
	return ret;
}

void read_client_configs(void)
{
	struct sockaddr_in addr;
	struct client_config *client;
	gchar **groups;

	srm_debug(SRM_DEBUG_CONFIG, NULL, "parsing config\n");
	groups = g_key_file_get_groups(config.keyfile, NULL);

	for (int i = 0; groups[i]; i++) {
		if (inet_pton(AF_INET, groups[i], &addr.sin_addr.s_addr) != 1)
			continue;
		client = parse_client_config(groups[i]);
		if (client) {
			memcpy(&client->addr, &addr, sizeof(addr));
			config.configs = g_list_append(config.configs, client);
		}
	}
	g_strfreev(groups);
}

void config_free(struct config *c)
{
	g_key_file_free(c->keyfile);
	g_free(c->chroot);
	g_free(c->root);
	g_free(c->interface);
	for (GList *p = c->configs; p; p = g_list_next(p))
		client_config_free(p->data);
	g_list_free(c->configs);
}
