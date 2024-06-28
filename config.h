#ifndef LANSRM_CONFIG_H
#define LANSRM_CONFIG_H

#include <glib.h>

struct ifcfg {
	struct sockaddr_in addr;
	char *name;
};

struct config {
	GList *configs;
	GKeyFile *keyfile;
	GList *interfaces;
	char *chroot;
	char *root;
	int foreground;
	int debug;
};
extern struct config config;

struct srm_volume {
	char *name;
	char *fullpath;
	char *path;
	int index;
	DIR *dir;
	int dirfd;
	gid_t gid;
	uid_t uid;
	mode_t umask;
	mode_t old_umask;
};

struct client_config *get_client_config(struct sockaddr_in *addr);
struct client_config *get_client_config_hwaddr(uint8_t *hwaddr);
void config_free(struct config *c);
void config_init(void);
void read_client_configs(void);
struct srm_volume *volume_by_name(struct client_config *client, const char *name);
void strip_dup_slashes(GString *s);

#endif
