#ifndef VM_FILE_H
#define VM_FILE_H
#include "filesys/file.h"
#include "vm/vm.h"

struct page;
enum vm_type;

/* ----------------------------------- project3-4_Memory Mapped Files ----------------------------------- */
// 매핑할 파일의 정보를 담아둘 파일 페이지 구조체 선언
struct file_page {
	// 파일
	struct file *file;
	// 파일의 길이
	size_t length;
	// 파일의 오프셋
	off_t offset;
};
/* ----------------------------------- project3-4_Memory Mapped Files ----------------------------------- */

void vm_file_init (void);
bool file_backed_initializer (struct page *page, enum vm_type type, void *kva);
void *do_mmap(void *addr, size_t length, int writable,
		struct file *file, off_t offset);
void do_munmap (void *va);
#endif
