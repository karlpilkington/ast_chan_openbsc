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

#include "asterisk/logger.h"
#include "asterisk/module.h"


/* ------------------------------------------------------------------------ */
/* Asterisk Module                                                          */
/* ---------------------------------------------------------------------{{{ */

static int
load_module(void)
{
	ast_log(LOG_NOTICE, "OpenBSC channel driver loaded\n");

	return AST_MODULE_LOAD_SUCCESS;
}


static int
unload_module(void)
{
	ast_log(LOG_NOTICE, "OpenBSC channel driver unloading.\n");

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

