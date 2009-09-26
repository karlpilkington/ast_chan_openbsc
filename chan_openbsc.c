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

#include <pthread.h>
#include <unistd.h>

#include "asterisk/channel.h"
#include "asterisk/logger.h"
#include "asterisk/module.h"


/* ------------------------------------------------------------------------ */
/* OpenBSC                                                                  */
/* ---------------------------------------------------------------------{{{ */


/* Main thread */
static int g_done;
static pthread_t g_main_tid;

static void *
openbsc_main(void *arg)
{
	ast_log(LOG_DEBUG, "OpenBSC channel main thread started\n");

	while (!g_done) {
		sleep(1.0);
		ast_log(LOG_DEBUG, "OpenBSC alive\n");
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
/* Channel driver                                                           */
/* ---------------------------------------------------------------------{{{ */

static struct ast_channel *
openbsc_chan_requester(const char *type, int format, void *data, int *cause)
{
	return 0;
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
	return 0;
}

static int
openbsc_chan_write(struct ast_channel *chan, struct ast_frame *frame)
{
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
/* Asterisk Module                                                          */
/* ---------------------------------------------------------------------{{{ */

static int
load_module(void)
{
	if (ast_channel_register(&openbsc_tech)) {
		ast_log(LOG_ERROR, "Unable to register channel class 'OpenBSC'\n");
		return AST_MODULE_LOAD_FAILURE;
	}

	if (openbsc_start()) {
		ast_channel_unregister(&openbsc_tech);
		ast_log(LOG_ERROR, "Unable to start OpenBSC main thread\n");
		return AST_MODULE_LOAD_FAILURE;
	}

	ast_log(LOG_NOTICE, "OpenBSC channel driver loaded\n");

	return AST_MODULE_LOAD_SUCCESS;
}


static int
unload_module(void)
{
	ast_log(LOG_NOTICE, "OpenBSC channel driver unloading.\n");

	openbsc_stop();

	ast_channel_unregister(&openbsc_tech);

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

