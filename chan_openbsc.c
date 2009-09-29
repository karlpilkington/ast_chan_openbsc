/*
 * Channel driver for the OpenBSC project ( http://openbsc.gnumonks.org )
 *
 * Copyright (C) 2009  Sylvain Munaut
 *
 * Sylvain Munaut <tnt@246tNt.com>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision: $")

#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>

#include <openbsc/debug.h>
#include <openbsc/db.h>
#include <openbsc/e1_input.h>
#include <openbsc/gsm_data.h>
#include <openbsc/select.h>
#include <openbsc/talloc.h>

#include "asterisk/channel.h"
#include "asterisk/io.h"
#include "asterisk/linkedlists.h"
#include "asterisk/logger.h"
#include "asterisk/module.h"
#include "asterisk/rtp.h"
#include "asterisk/sched.h"
#include "asterisk/utils.h"


enum call_direction {
	MOBILE_ORIGINATED,
	MOBILE_TERMINATED,
};

	/* Uses the owner lock, or g_openbsc_lock if owner==NULL */
struct openbsc_chan_priv {
	struct ast_channel *owner;

	u_int32_t callref;
	enum call_direction dir;

	struct ast_rtp *rtp;

	AST_LIST_ENTRY(openbsc_chan_priv) _list;
};

static AST_RWLIST_HEAD_STATIC(g_privs, openbsc_chan_priv);
static u_int32_t g_nextcallref = 0x00000001;	/* uses g_privs lock */

static struct sched_context *g_sched_ctx = NULL;
static struct io_context *g_io_ctx = NULL;

static struct sockaddr_in g_bindaddr = { 0, };
static struct in_addr g_ourip;


AST_MUTEX_DEFINE_STATIC(g_openbsc_lock);


static struct openbsc_chan_priv *_openbsc_chan_priv_find(u_int32_t callref);
static int mncc_recv_ast(struct gsm_network *net, int msg_type, void *arg);


/* ------------------------------------------------------------------------ */
/* OpenBSC                                                                  */
/* ---------------------------------------------------------------------{{{ */

struct openbsc_config {
	char config_file[PATH_MAX];
	char db_file[PATH_MAX];
	char pcap_file[PATH_MAX];
	char debug_filter[128];
	char bindaddr[128];
	int debug_color;
	int debug_timestamp;
	int reject_cause;
};

struct gsm_network *bsc_gsmnet = 0;

extern int bsc_bootstrap_network(int (*mmc_rev)(struct gsm_network *, int, void *),
				 const char *cfg_file);
extern int bsc_shutdown_net(struct gsm_network *net);


/* PCAP logging */
static int
create_pcap_file(char *file)
{
	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	int fd = open(file, O_WRONLY|O_TRUNC|O_CREAT, mode);

	if (fd < 0) {
		ast_log(LOG_ERROR, "Failed to open file for pcap\n");
		return -1;
	}

	e1_set_pcap_fd(fd);

	return 0;
}

/* Main thread */
static int g_done;
static pthread_t g_main_tid;

static int
openbsc_init(struct openbsc_config *cfg)
{
	int rc;

	/* seed the PRNG */
	srand(time(NULL));

	/* debug init */
	if (cfg->debug_filter[0])
		debug_parse_category_mask(cfg->debug_filter);
	debug_use_color(cfg->debug_color);
	debug_timestamp(cfg->debug_timestamp);

	/* pcap file init */
	if (cfg->pcap_file[0])
		create_pcap_file(cfg->pcap_file);

	/* other config */
	if (cfg->reject_cause >= 0)
		gsm0408_set_reject_cause(cfg->reject_cause);

	/* talloc contexts init */
	tall_bsc_ctx = talloc_named_const(NULL, 1, "openbsc");
	talloc_ctx_init();

	/* submod init */
	on_dso_load_token();
	on_dso_load_rrlp();

	/* HLR/DB init */
	if (db_init(cfg->db_file)) {
		ast_log(LOG_ERROR, "DB: Failed to init database. Please check the option settings.\n");
		return -1;
	}
	ast_log(LOG_DEBUG, "DB: Database initialized.\n");

	if (db_prepare()) {
		ast_log(LOG_ERROR, "DB: Failed to prepare database.\n");
		return -1;
	}
	ast_log(LOG_DEBUG, "DB: Database prepared.\n");

	/* Bootstrap all network stuff */
	rc = bsc_bootstrap_network(mncc_recv_ast, cfg->config_file);
	if (rc < 0) {
		ast_log(LOG_ERROR, "Failed to bootstrap network\n");
		return -1;
	}

	return 0;
}

static void
openbsc_destroy()
{
	bsc_shutdown_net(bsc_gsmnet);	/* FIXME not everything is freed !!! */
}

static void *
openbsc_main(void *arg)
{
	int work;

	ast_log(LOG_DEBUG, "OpenBSC channel main thread started\n");

	while (!g_done) {
		ast_mutex_lock(&g_openbsc_lock);

		bsc_upqueue(bsc_gsmnet);
		work = bsc_select_main(1);

		ast_mutex_unlock(&g_openbsc_lock);

		if (!work)
			usleep(100 * 1000);
	}

	ast_log(LOG_DEBUG, "OpenBSC channel main thread exiting\n");

	return NULL;
}

static int
openbsc_start(void)
{
	g_done = 0;
	return pthread_create(&g_main_tid, NULL, openbsc_main, NULL);
}

static void
openbsc_stop(void)
{
	g_done = 1;
	pthread_join(g_main_tid, NULL);
}

/* }}} */


/* ------------------------------------------------------------------------ */
/* MNCC                                                                     */
/* ---------------------------------------------------------------------{{{ */

static struct gsm_mncc *
mncc_create(int msg_type, u_int32_t callref)
{
	struct gsm_mncc *mncc;

	mncc = (struct gsm_mncc *)ast_malloc(sizeof(struct gsm_mncc));
	memset(mncc, 0x00, sizeof(struct gsm_mncc));

	mncc->msg_type = msg_type;
	mncc->callref = callref;

	return mncc;
}

static int
mncc_send_and_free(struct gsm_network *net, unsigned int msg_type, void *data)
{
	int ret;

	ret = mncc_send(net, msg_type, data);
	free(data);

	return ret;
}


static int
mncc_recv_ast(struct gsm_network *net, int msg_type, void *arg)
{
	struct gsm_mncc *data = arg;
	struct gsm_mncc *s;
	struct openbsc_chan_priv *p;

	p = _openbsc_chan_priv_find(data->callref);

	DEBUGP(DMNCC, "Received message %s (priv=%p)\n", get_mncc_name(msg_type), p);

	switch(msg_type) {

	/* FIXME handle MNCC messages here ! */

	default:
		break;
	}

	return 0;
}

/* }}} */


/* ------------------------------------------------------------------------ */
/* Channel driver                                                           */
/* ---------------------------------------------------------------------{{{ */

static const struct ast_channel_tech openbsc_tech;


/* Helpers */

static struct ast_channel *
_openbsc_chan_new(struct openbsc_chan_priv *p, int state)
{
	struct ast_channel *chan = NULL;

	chan = ast_channel_alloc(1, state, 0, NULL, "", "", "", 0, "OpenBSC/callref-%08x", p->callref);
	if (!chan)
		return NULL;

	chan->tech = &openbsc_tech;
	chan->nativeformats = AST_FORMAT_GSM;
	chan->readformat    = AST_FORMAT_GSM;
	chan->writeformat   = AST_FORMAT_GSM;

	chan->tech_pvt = p;
	p->owner = chan;

	ast_channel_set_fd(chan, 0, ast_rtp_fd(p->rtp));
	ast_channel_set_fd(chan, 1, ast_rtcp_fd(p->rtp));

	ast_module_ref(ast_module_info->self);

	return chan;
}

static void
_openbsc_chan_detach(struct ast_channel *chan)
{
	struct openbsc_chan_priv *p = chan->tech_pvt;

	ast_channel_set_fd(chan, 0, -1);
	ast_channel_set_fd(chan, 1, -1);

	chan->tech_pvt = NULL;
	p->owner = NULL;

	ast_module_unref(ast_module_info->self);
}

static struct openbsc_chan_priv *
_openbsc_chan_priv_new(u_int32_t callref, enum call_direction dir)
{
	struct openbsc_chan_priv *p = NULL;

	AST_RWLIST_WRLOCK(&g_privs);

	/* Auto callref */
	if (!callref) {
		callref = g_nextcallref;
		g_nextcallref = (g_nextcallref + 1) & 0x7fffffff;
	}

	/* Alloc and init the structure */
	p = ast_calloc(1, sizeof(*p));
	if (!p) {
		ast_log(LOG_ERROR, "Failed to allocate channel private structure\n");
		goto error;
	}

	p->callref = callref;
	p->dir = dir;

	/* RTP init */
	p->rtp = ast_rtp_new_with_bindaddr(g_sched_ctx, g_io_ctx, 1, 0, g_bindaddr.sin_addr);
	if (!p->rtp) {
		ast_log(LOG_ERROR, "Failed to allocate channel RTP stream\n");
		goto error;
	}

	ast_rtp_pt_clear(p->rtp);

	/* Finally add to the list */
	AST_RWLIST_INSERT_HEAD(&g_privs, p, _list);

	AST_RWLIST_UNLOCK(&g_privs);

	return p;

error:
	if (p)
		ast_free(p);
	AST_RWLIST_UNLOCK(&g_privs);
	return NULL;
}

static void
_openbsc_chan_priv_destroy(struct openbsc_chan_priv *p)
{
	/* Remove entry from the list */
	AST_RWLIST_WRLOCK(&g_privs);
	AST_RWLIST_REMOVE(&g_privs, p, _list);
	AST_RWLIST_UNLOCK(&g_privs);

	/* Destroy rtp */
	ast_rtp_destroy(p->rtp);

	/* Free memory */
	ast_free(p);
}

static struct openbsc_chan_priv *
_openbsc_chan_priv_find(u_int32_t callref)
{
		/* What about race conditions ? I could find a channel with the
		 * given callref but then have it deleted under my nose ... */
	struct openbsc_chan_priv *c, *h = NULL;
	AST_RWLIST_RDLOCK(&g_privs);
	AST_RWLIST_TRAVERSE(&g_privs, c, _list) {
		if (c->callref == callref) {
			h = c;
			break;
		}
	}
	AST_RWLIST_UNLOCK(&g_privs);
	return h;
}


/* Interface implementation */

static struct ast_channel *
openbsc_chan_requester(const char *type, int format, void *data, int *cause)
{
	struct openbsc_chan_priv *p = NULL;
	struct ast_channel *chan = NULL;

	p = _openbsc_chan_priv_new(0, MOBILE_TERMINATED);
	if (!p) {
		ast_log(LOG_ERROR, "Failed to create channel private structure\n");
		goto error;
	}

	chan = _openbsc_chan_new(p, AST_STATE_DOWN);
	if (!chan) {
		ast_log(LOG_ERROR, "Failed to create channel structure\n");
		goto error;
	}

	return chan;

error:
	if (p)
		_openbsc_chan_priv_destroy(p);
	return NULL;
}

#if 0
static int
openbsc_chan_devicestate(void *data)
{
	return 0;
}
#endif

static int
openbsc_chan_send_digit_begin(struct ast_channel *chan, char digit)
{
	return 0;
}

static int
openbsc_chan_send_digit_end(struct ast_channel *chan, char digit, unsigned int duration)
{
	return 0;
}

static int
openbsc_chan_call(struct ast_channel *chan, char *addr, int timeout)
{
	return 0;
}

static int
openbsc_chan_hangup(struct ast_channel *chan)
{
	struct openbsc_chan_priv *p = chan->tech_pvt;

	_openbsc_chan_detach(chan);
	_openbsc_chan_priv_destroy(p); /* FIXME shouldn't be done here in the future */

	return 0;
}

static int
openbsc_chan_answer(struct ast_channel *chan)
{
	return 0;
}

static struct ast_frame *
openbsc_chan_read(struct ast_channel *chan)
{
	struct openbsc_chan_priv *p = chan->tech_pvt;
	struct ast_frame *f;

	if (!p->rtp)
		return &ast_null_frame;

	switch (chan->fdno) {
		case 0:
			f = ast_rtp_read(p->rtp);
			break;

		case 1:
			f = ast_rtcp_read(p->rtp);
			break;

		default:
			f = &ast_null_frame;
	}
}

static int
openbsc_chan_write(struct ast_channel *chan, struct ast_frame *frame)
{
	struct openbsc_chan_priv *p = chan->tech_pvt;

	switch (frame->frametype) {
	case AST_FRAME_VOICE:
		return p->rtp ? ast_rtp_write(p->rtp, frame) : 0;

	default:
		ast_log(LOG_WARNING,
			"Can't send %d type frames with write\n",
			frame->frametype
		);
	}

	return 0;
}

#if 0
static int
openbsc_chan_send_text(struct ast_channel *chan, const char *text)
{
	return 0;
}

static int
openbsc_chan_send_image(struct ast_channel *chan, struct ast_frame *frame)
{
	return 0;
}

static int
openbsc_chan_send_html(struct ast_channel *chan, int subclass, const char *data, int len)
{
	return 0;
}

static struct ast_frame *
openbsc_chan_exception(struct ast_channel *chan)
{
	return 0;
}

static enum ast_bridge_result
openbsc_chan_bridge(struct ast_channel *c0, struct ast_channel *c1,
		int flags, struct ast_frame **fo, struct ast_channel **rc, int timeoutms)
{
	return 0;
}

static enum ast_bridge_result
openbsc_chan_early_bridge(struct ast_channel *c0, struct ast_channel *c1)
{
	return 0;
}
#endif

static int
openbsc_chan_indicate(struct ast_channel *c, int condition, const void *data, size_t datalen)
{
	return 0;
}

static int
openbsc_chan_fixup(struct ast_channel *oldchan, struct ast_channel *newchan)
{
	return 0;
}

#if 0
static int
openbsc_chan_setoption(struct ast_channel *chan, int option, void *data, int datalen)
{
	return 0;
}

static int
openbsc_chan_queryoption(struct ast_channel *chan, int option, void *data, int *datalen)
{
	return 0;
}

static int
openbsc_chan_transfer(struct ast_channel *chan, const char *newdest)
{
	return 0;
}

static int
openbsc_chan_write_video(struct ast_channel *chan, struct ast_frame *frame)
{
	return 0;
}

static int
openbsc_chan_write_text(struct ast_channel *chan, struct ast_frame *frame)
{
	return 0;
}

static struct ast_channel *
openbsc_chan_bridged_channel(struct ast_channel *chan, struct ast_channel *bridge)
{
	return 0;
}

static int
openbsc_chan_func_channel_read(struct ast_channel *chan, const char *function, char *data, char *buf, size_t len)
{
	return 0;
}

static int
openbsc_chan_func_channel_write(struct ast_channel *chan, const char *function, char *data, const char *value)
{
	return 0;
}

static struct ast_channel*
openbsc_chan_get_base_channel(struct ast_channel *chan)
{
	return 0;
}

static int
openbsc_chan_set_base_channel(struct ast_channel *chan, struct ast_channel *base)
{
	return 0;
}

static const char *
openbsc_chan_get_pvt_uniqueid(struct ast_channel *chan)
{
	return 0;
}
#endif


static const struct ast_channel_tech openbsc_tech = {
	.type = "OpenBSC",
	.description = "Channel driver for OpenBSC",
	.capabilities = AST_FORMAT_GSM, /* FIXME */
	.properties = 0, /* FIXME */
	.requester = openbsc_chan_requester,
	/* .devicestate = openbsc_chan_devicestate, */
	.send_digit_begin = openbsc_chan_send_digit_begin,
	.send_digit_end = openbsc_chan_send_digit_end,
	.call = openbsc_chan_call,
	.hangup = openbsc_chan_hangup,
	.answer = openbsc_chan_answer,
	.read = openbsc_chan_read,
	.write = openbsc_chan_write,
	/* .send_text = openbsc_chan_send_text, */
	/* .send_image = openbsc_chan_send_image, */
	/* .send_html = openbsc_chan_send_html, */
	/* .exception = openbsc_chan_exception, */
	/* .bridge = openbsc_chan_bridge, */
	/* .early_bridge = openbsc_chan_early_bridge, */
	.indicate = openbsc_chan_indicate,
	.fixup = openbsc_chan_fixup,
	/* .setoption = openbsc_chan_setoption, */
	/* .queryoption = openbsc_chan_queryoption, */
	/* .transfer = openbsc_chan_transfer, */
	/* .write_video = openbsc_chan_write_video, */
	/* .write_text = openbsc_chan_write_text, */
	/* .bridged_channel = openbsc_chan_bridged_channel, */
	/* .func_channel_read = openbsc_chan_func_channel_read, */
	/* .func_channel_write = openbsc_chan_func_channel_write, */
	/* .get_base_channel = openbsc_chan_get_base_channel, */
	/* .set_base_channel = openbsc_chan_set_base_channel, */
	/* .get_pvt_uniqueid = openbsc_chan_get_pvt_uniqueid, */
};

/* }}} */


/* ------------------------------------------------------------------------ */
/* RTP interface                                                            */
/* ---------------------------------------------------------------------{{{ */

/* Main thread */
static pthread_t g_rtp_tid;

static void *
openbsc_rtp_main(void *data)
{
	int rv;

	while(1) {
		pthread_testcancel();
		/* Wait for sched or io */
		rv = ast_sched_wait(g_sched_ctx);
		if ((rv < 0) || (rv > 1000)) {
			rv = 1000;
		}
		rv = ast_io_wait(g_io_ctx, rv);
		if (rv >= 0) {
			ast_sched_runq(g_sched_ctx);
		}
	}

	return NULL; /* Never reached */
}

static int
openbsc_rtp_start(void)
{
	return ast_pthread_create(&g_rtp_tid, NULL, openbsc_rtp_main, NULL);
}

static void
openbsc_rtp_stop(void)
{
	pthread_cancel(g_rtp_tid);
	pthread_join(g_rtp_tid, NULL);
}


/* Interface implementation */
static enum ast_rtp_get_result
openbsc_rtp_get_peer(struct ast_channel *chan, struct ast_rtp **rtp)
{
	struct openbsc_chan_priv *p = chan->tech_pvt;
	if (p && p->rtp) {
		*rtp = p->rtp;
		return AST_RTP_TRY_PARTIAL;
	}
	return AST_RTP_GET_FAILED;
}

static int
openbsc_rtp_set_peer(struct ast_channel *chan,
		struct ast_rtp *peer, struct ast_rtp *vpeer, struct ast_rtp *tpeer,
		int codecs, int nat_active)
{
	/* Direct media path not supported */
	ast_log(LOG_WARNING, "set_rtp_peer is not supported for now");
	return 0;
}

static int
openbsc_rtp_get_codec(struct ast_channel *chan)
{
	return chan->nativeformats;
}


static struct ast_rtp_protocol openbsc_rtp = {
	.type = "OpenBSC",
	.get_rtp_info  = openbsc_rtp_get_peer,
	.set_rtp_peer  = openbsc_rtp_set_peer,
	.get_codec     = openbsc_rtp_get_codec,
};

/* }}} */


/* ------------------------------------------------------------------------ */
/* Asterisk Module                                                          */
/* ---------------------------------------------------------------------{{{ */

static struct openbsc_config *
config_module(void)
{
	const char *config_filename = "openbsc.conf";
	const struct ast_flags config_flags = { 0 };

	struct ast_config *ast_cfg;
	struct ast_variable *v;
	struct openbsc_config *cfg;

	/* Config structure */
	cfg = calloc(1, sizeof(struct openbsc_config));
	if (!cfg) {
		ast_log(LOG_ERROR, "Failed to allocate memory for config structure\n");
		return NULL;
	}

	/* Default options */
	strcpy(cfg->config_file, "/etc/openbsc.conf");
	strcpy(cfg->db_file, "/var/lib/openbsc/hlr.sqlite3");
	strcpy(cfg->debug_filter, "DRLL:DCC:DMM:DRR:DRSL:DNM");
	cfg->debug_color = 1;
	cfg->debug_timestamp = 0;
	cfg->reject_cause = -1;

	/* Asterisk config load */
	ast_cfg = ast_config_load(config_filename, config_flags);
	if (!ast_cfg) {
		ast_log(LOG_WARNING, "Unable to load config %s, fall back to default values\n", config_filename);
		return cfg;
	} else if (ast_cfg == CONFIG_STATUS_FILEINVALID) {
		ast_log(LOG_ERROR, "Config file %s is in an invalid format.  Aborting.\n", config_filename);
		return NULL;
	}

	/* Parse the K,V of the config file */
	for (v = ast_variable_browse(ast_cfg, "general"); v; v = v->next)
	{
		if (!strcasecmp(v->name, "config_file")) {
			ast_copy_string(cfg->config_file, v->value, sizeof(cfg->config_file));
		} else if (!strcasecmp(v->name, "db_file")) {
			ast_copy_string(cfg->db_file, v->value, sizeof(cfg->db_file));
		} else if (!strcasecmp(v->name, "debug")) {
			ast_copy_string(cfg->debug_filter, v->value, sizeof(cfg->debug_filter));
		} else if (!strcasecmp(v->name, "debug_color")) {
			cfg->debug_color = ast_true(v->value) ? 1 : 0;
		} else if (!strcasecmp(v->name, "debug_timestamp")) {
			cfg->debug_timestamp = ast_true(v->value) ? 1 : 0;
		} else if (!strcasecmp(v->name, "reject_cause")) {
			cfg->reject_cause = atoi(v->value);
		} else if (!strcasecmp(v->name, "pcap_file")) {
			ast_copy_string(cfg->pcap_file, v->value, sizeof(cfg->pcap_file));
		} else if (!strcasecmp(v->name, "bindaddr")) {
			ast_copy_string(cfg->bindaddr, v->value, sizeof(cfg->bindaddr));
		} else {
			ast_log(LOG_WARNING, "Unknown config key %s ignored\n", v->name);
		}
	}

	/* Release asterisk config object */
	ast_config_destroy(ast_cfg);

	return cfg;
}

static int
load_module(void)
{
	struct openbsc_config *cfg;
	struct ast_hostent ahp;
	struct hostent *hp;
	int rv;

	cfg = config_module();
	if (!cfg)
		return AST_MODULE_LOAD_DECLINE;

	if (cfg->bindaddr[0]) {
		if (!(hp = ast_gethostbyname(cfg->bindaddr, &ahp))) {
			ast_log(LOG_WARNING, "Invalid address: %s\n", cfg->bindaddr);
		} else {
			memcpy(&g_bindaddr.sin_addr, hp->h_addr, sizeof(g_bindaddr.sin_addr));
		}
	}

	if (ast_find_ourip(&g_ourip, g_bindaddr)) {
		ast_log(LOG_ERROR, "Unable to get own IP address, OpenBSC disabled\n");
		goto error_free_cfg;
	}

	rv = openbsc_init(cfg);
	if (rv) {
		ast_log(LOG_ERROR, "Failed to initialize OpenBSC\n");
		goto error_free_cfg;
	}

	g_io_ctx = io_context_create();
	if (!g_io_ctx) {
		ast_log(LOG_ERROR, "Unable to create IO context\n");
		goto error_free;
	}

	g_sched_ctx = sched_context_create();
	if (!g_sched_ctx) {
		ast_log(LOG_ERROR, "Unable to create Scheduling context\n");
		goto error_free;
	}

	if (ast_rtp_proto_register(&openbsc_rtp)) {
		ast_log(LOG_ERROR, "Unable to RTP protocol class 'OpenBSC'\n");
		goto error_free;
	}

	if (ast_channel_register(&openbsc_tech)) {
		ast_log(LOG_ERROR, "Unable to register channel class 'OpenBSC'\n");
		goto error_unreg_rtp;
	}

	if (openbsc_rtp_start()) {
		ast_log(LOG_ERROR, "Unable to start OpenBSC RTP thread\n");
		goto error_unreg_chan;
	}

	if (openbsc_start()) {
		ast_log(LOG_ERROR, "Unable to start OpenBSC main thread\n");
		goto error_stoprtp;
	}

	ast_log(LOG_NOTICE, "OpenBSC channel driver loaded\n");

	return AST_MODULE_LOAD_SUCCESS;

error_stoprtp:
	openbsc_rtp_stop();

error_unreg_chan:
	ast_channel_unregister(&openbsc_tech);

error_unreg_rtp:
	ast_rtp_proto_unregister(&openbsc_rtp);

error_free:
	if (g_sched_ctx)
		sched_context_destroy(g_sched_ctx);

	if (g_io_ctx)
		io_context_destroy(g_io_ctx);

	openbsc_destroy();

error_free_cfg:
	free(cfg);

	return AST_MODULE_LOAD_FAILURE;
}


static int
unload_module(void)
{
	ast_log(LOG_NOTICE, "OpenBSC channel driver unloading.\n");

	openbsc_stop();

	openbsc_rtp_stop();

	ast_channel_unregister(&openbsc_tech);
	ast_rtp_proto_unregister(&openbsc_rtp);
	sched_context_destroy(g_sched_ctx);
	io_context_destroy(g_io_ctx);

	openbsc_destroy();

	return 0;
}

static int
reload_module(void)
{
	return 0;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_DEFAULT, "Channel driver for OpenBSC",
	.load   = load_module,
	.unload = unload_module,
	.reload = reload_module,
);

/* }}} */

