#include <sys/signal.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "lansrm.h"
#include "rmp.h"
#include "srm.h"
#include "epoll.h"
#include "config.h"
#include "debug.h"
#include <glib.h>

static int client_compare(const void *a, const void *b, void *data)
{
	(void)data;

	return memcmp(a, b, sizeof(struct sockaddr_in));
}

static void usage(char *name)
{
	printf("%s: usage:\n"
	       "-f, --foreground             don't fork into background\n"
	       "-c, --chroot <directory>     chroot to <directory>\n"
	       "-r, --root <directory>       use <directory> as base for SRM files\n"
	       "-d, --debug <level>          set debug level to <level>\n"
	       "        1 = REQUEST\n"
	       "        2 = RESPONSE\n"
	       "        4 = CONNECT\n"
	       "        8 = XFER\n"
	       "       16 = FILE\n"
	       "       32 = PACKET_RX\n"
	       "       64 = PACKET_TX\n"
	       "      128 = ERROR\n"
	       "      256 = EPOLL\n", name);
}

static const struct option longopts[] = {
	{ "interface", required_argument, 0, 'i' },
	{ "debug", required_argument, 0, 'd' },
	{ "foreground", no_argument, 0, 'f' },
	{ "chroot", required_argument, 0, 'c' },
	{ "root", required_argument, 0, 'r' },
	{ "help", no_argument, 0, 'h' }
};

static void sighandler(int sig)
{
	(void)sig;

	shouldexit = 1;
}

static void client_destroy(gpointer data)
{
	struct srm_client *client = data;

	g_tree_destroy(client->files);
	g_free(client->ipstr);
	g_free(client);
}

int main(int argc, char **argv)
{
	int ret, longind = 0;
	GTree *clients;
	GError *gerr;

	config.keyfile = g_key_file_new();
	if (g_key_file_load_from_file(config.keyfile, "/etc/srm.ini", G_KEY_FILE_NONE, &gerr)) {
		config.debug = g_key_file_get_integer(config.keyfile, "global", "debug", NULL);
		config.chroot = g_key_file_get_string(config.keyfile, "global", "chroot", NULL);
		config.root = g_key_file_get_string(config.keyfile, "global", "root", NULL);
		config.foreground = g_key_file_get_boolean(config.keyfile, "global", "foreground", NULL);
	}

	for (;;) {
		char c = getopt_long(argc, argv, "d:fhcr:", longopts, &longind);
		if (c == -1)
			break;
		switch(c) {
		case 'd':
			config.debug = strtoul(optarg, NULL, 0);
			break;
		case 'f':
			config.foreground = 1;
			break;
		case 'c':
			g_free(config.chroot);
			config.chroot = strdup(optarg);
			break;
		case 'r':
			g_free(config.root);
			config.root = strdup(optarg);
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		}
	}

	config_init();

	read_client_configs();
	if (signal(SIGTERM, sighandler) == SIG_ERR) {
		perror("error registering SIGTERM handler\n");
		goto error;
	}

	if (signal(SIGINT, sighandler) == SIG_ERR) {
		perror("error registering SIGINT handler\n");
		goto error;
	}

	if (!config.root)
		config.root = strdup("/");

	// TODO: cleanup in error path
	clients = g_tree_new_full(client_compare, NULL, NULL, client_destroy);

	if (epoll_init() == -1)
		goto error;

	srm_init(clients);
	rmp_init(clients);

	if (!config.foreground && daemon(0, 0) == -1) {
		perror("daemon");
		goto error;
	}

	if (config.chroot && chroot(config.chroot) == -1) {
		perror("chroot: %m\n");
		goto error;
	}
	if (chdir("/") == -1) {
		perror("chdir");
		goto error;
	}
	ret = epoll_loop();
error:
	srm_exit();
	rmp_exit();
	epoll_exit();
	g_tree_destroy(clients);
	config_free(&config);
	return ret;
}
