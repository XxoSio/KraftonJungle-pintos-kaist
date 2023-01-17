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

/* ------------------------- project3-2-1_Anonymous Page_Lazy Loading for Executable ------------------------ */
// aux 구조체 선언
struct load_aux{
	// 파일로부터 읽을 바이트 수
	size_t page_read_bytes;
	// 0으로 채워줄 바이트 수
	size_t page_zero_bytes;
	// 파일
	struct file *file;
	// 파일의 오프셋(위치 주소)
	off_t ofs;
};
/* ------------------------- project3-2-1_Anonymous Page_Lazy Loading for Executable ------------------------ */

/* ----------------------------------- project3-4_Memory Mapped Files ----------------------------------- */
// 파일 메모리 매핑때 재사용을 위해 선언
bool lazy_load_segment (struct page *page, void *aux);
/* ----------------------------------- project3-4_Memory Mapped Files ----------------------------------- */

#endif /* userprog/process.h */
