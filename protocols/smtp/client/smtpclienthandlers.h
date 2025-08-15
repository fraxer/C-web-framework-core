#ifndef __SMTP_CLIENT_HANDLERS__
#define __SMTP_CLIENT_HANDLERS__

#include "connection_c.h"

void set_smtp_client_command(connection_t* connection);
void set_smtp_client_content(connection_t* connection);
void set_smtp_client_tls(connection_t* connection);
int tls_smtp_client_read(connection_t* connection);
int tls_smtp_client_write(connection_t* connection);
int smtp_client_read(connection_t* connection);
int smtp_client_write_command(connection_t* connection);
int smtp_client_write_content(connection_t* connection);

#endif
