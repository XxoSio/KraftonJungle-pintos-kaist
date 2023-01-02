#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

/* ------------------------------ project2-3-1_System calls-File Descriptor ------------------------------ */
#define FDT_LIMIT 512*3
/* ------------------------------ project2-3-1_System calls-File Descriptor ------------------------------ */

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

/* ------------------------------ project2-1_Argument Passing ------------------------------ */
void argument_stack(char **argv, int argc, struct intr_frame *if_);
/* ------------------------------ project2-1_Argument Passing ------------------------------ */

#endif /* userprog/process.h */
