#ifndef __SIGNAL__
#define __SIGNAL__

void signal_init(void);
void signal_before_terminate(int);
void signal_block_usr1(void);

#endif