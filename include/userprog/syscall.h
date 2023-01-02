#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

/* ----------------------------------- project2-3-1_System calls-File Descriptor ----------------------------------- */
// 표준 입력
#define STDIN 1	
// 표준 출력
#define STDOUT 2

struct lock file_lock;
/* ----------------------------------- project2-3-1_System calls-File Descriptor ----------------------------------- */

#endif /* userprog/syscall.h */
