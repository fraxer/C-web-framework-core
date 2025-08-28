#ifndef __MULTIPLEXINGSERVER__
#define __MULTIPLEXINGSERVER__

#include "appconfig.h"

int mpxserver_run(appconfig_t* appconfig, void(*thread_worker_threads_pause)(appconfig_t* config));

#endif