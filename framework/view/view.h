#ifndef __VIEW__
#define __VIEW__

#include "viewcommon.h"

char* render(json_doc_t* document, view_escape_e escape, const char* storage_name, const char* path_format, ...);

#endif
