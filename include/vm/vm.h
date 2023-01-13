#ifndef VM_VM_H
#define VM_VM_H
#include <stdbool.h>
#include "threads/palloc.h"

/* ----------------------------------- project3-1_Memory Management ----------------------------------- */
#include "lib/kernel/hash.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
/* ----------------------------------- project3-1_Memory Management ----------------------------------- */

enum vm_type {
	/* page not initialized */
	VM_UNINIT = 0,
	/* page not related to the file, aka anonymous page */
	VM_ANON = 1,
	/* page that realated to the file */ 
	VM_FILE = 2,
	/* page that hold the page cache, for project 4 */
	VM_PAGE_CACHE = 3,

	/* ------------------------- project3-2-1_Anonymous Page_Lazy Loading for Executable ------------------------ */
	// 스택인 경우 구분
	// PintOS에서는 총 stack의 크기를 1MB(0x100000)로 제한하기 때문에 받아온 주소가 USER_STACK으로부터 1MB 사이에 있는지 확인
	// VM_ANON || (1 << 3)
	// ANON 페이지로 만들 UNINIT 페이지를 stack_bottom에서 위로 PGSIZE만큼(1 PAGE) 만듦
	// 이 때 TYPE에 VM_MARKER_0 flag를 추가함으로써 이 페이지가 STACK에 있다는 것을 표시함
	VM_STACK = 9,
	/* ------------------------- project3-2-1_Anonymous Page_Lazy Loading for Executable ------------------------ */

	/* Bit flags to store state */

	/* Auxillary bit flag marker for store information. You can add more
	 * markers, until the value is fit in the int. */
	// 저장 정보를 위한 보조 비트 플래그 마커
	VM_MARKER_0 = (1 << 3),
	VM_MARKER_1 = (1 << 4),

	/* DO NOT EXCEED THIS VALUE. */
	VM_MARKER_END = (1 << 31),
};

#include "vm/uninit.h"
#include "vm/anon.h"
#include "vm/file.h"
#ifdef EFILESYS
#include "filesys/page_cache.h"
#endif

struct page_operations;
struct thread;

#define VM_TYPE(type) ((type) & 7)

/* The representation of "page".
 * This is kind of "parent class", which has four "child class"es, which are
 * uninit_page, file_page, anon_page, and page cache (project4).
 * DO NOT REMOVE/MODIFY PREDEFINED MEMBER OF THIS STRUCTURE. */
 // 가상메모리에서의 페이지를 의미
struct page {
	const struct page_operations *operations;
	void *va;              /* Address in terms of user space */
	struct frame *frame;   /* Back reference for frame */

	/* Your implementation */
	/* ----------------------------------- project3-1_Memory Management ----------------------------------- */
	// 가상 메모리 페이지에 포함되는 해시 구조체 멤버 선언
	struct hash_elem hash_elem;

	// 스택 표시
	bool stack;
	// 쓰기 가능 여부
	bool writable;
	/* ----------------------------------- project3-1_Memory Management ----------------------------------- */

	/* Per-type data are binded into the union.
	 * Each function automatically detects the current union */
	// 여러개의 맴버를 가질 수 있지만, 한번에 맴버중하나의 값만을 가질 수 있음
	union {
		struct uninit_page uninit;
		struct anon_page anon;
		struct file_page file;
#ifdef EFILESYS
		struct page_cache page_cache;
#endif
	};
};

/* The representation of "frame" */
struct frame {
	void *kva;
	struct page *page;
};

/* The function table for page operations.
 * This is one way of implementing "interface" in C.
 * Put the table of "method" into the struct's member, and
 * call it whenever you needed. */
// 페이지 작업에 대한 함수 테이블
struct page_operations {
	bool (*swap_in) (struct page *, void *);
	bool (*swap_out) (struct page *);
	void (*destroy) (struct page *);
	enum vm_type type;
};

#define swap_in(page, v) (page)->operations->swap_in ((page), v)
#define swap_out(page) (page)->operations->swap_out (page)
#define destroy(page) \
	if ((page)->operations->destroy) (page)->operations->destroy (page)

/* ----------------------------------- project3-1_Memory Management ----------------------------------- */
/* Representation of current process's memory space.
 * We don't want to force you to obey any specific design for this struct.
 * All designs up to you for this. */
struct supplemental_page_table {
	// 해시 테이블 선언
	struct hash hash_table;
};
/* ----------------------------------- project3-1_Memory Management ----------------------------------- */

#include "threads/thread.h"
void supplemental_page_table_init (struct supplemental_page_table *spt);
bool supplemental_page_table_copy (struct supplemental_page_table *dst,
		struct supplemental_page_table *src);
void supplemental_page_table_kill (struct supplemental_page_table *spt);
struct page *spt_find_page (struct supplemental_page_table *spt,
		void *va);
bool spt_insert_page (struct supplemental_page_table *spt, struct page *page);
void spt_remove_page (struct supplemental_page_table *spt, struct page *page);

void vm_init (void);
bool vm_try_handle_fault (struct intr_frame *f, void *addr, bool user,
		bool write, bool not_present);

#define vm_alloc_page(type, upage, writable) \
	vm_alloc_page_with_initializer ((type), (upage), (writable), NULL, NULL)
bool vm_alloc_page_with_initializer (enum vm_type type, void *upage,
		bool writable, vm_initializer *init, void *aux);
void vm_dealloc_page (struct page *page);
bool vm_claim_page (void *va);
enum vm_type page_get_type (struct page *page);

#endif  /* VM_VM_H */
