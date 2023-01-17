/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"

#include "userprog/process.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* ------------------------- project3-4_Memory Mapped Files ------------------------ */
/* Do the mmap */
// fd로 열린 파일의 오프셋 바이트부터 length바이트 만큼을 프로세스의 가상 주소 공간의 주소 addr에 매핑
// 매핑된 가상주소 반환
void *
do_mmap (void *addr, size_t length, int writable, struct file *file, off_t offset) {
	// file_reopen()을 사용하여 인자로 받은 파일과 동일한 inod에 대한 새 파일을 열고 반환
	struct file_page *open_file = file_reopen(file);
	// 파일에서 읽을 바이트
	size_t read_bytes = file_length(file) < length ? file_length(file) : length;
	// 0으로 채워줄 바이트
    size_t zero_bytes = PGSIZE - (read_bytes % PGSIZE);
	// 파일의 오프셋
	off_t ofs = offset;
	
	// 페이지 확장시 리턴 주소값 변경 방지
	void *return_addr = addr;

	// 파일이 NULL이거나 읽을 바이트의 수가 0이면 NULL 반환
	if(open_file == NULL || read_bytes == 0)
		return NULL;

	// 에러 체크 - 파일의 전체 길이가 PGSIZE의 배수가 아닌 경우 
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);

    while (read_bytes > 0 || zero_bytes > 0) {
        /* Do calculate how to fill this page.
         * We will read PAGE_READ_BYTES bytes from FILE
         * and zero the final PAGE_ZERO_BYTES bytes. */
        // FILE에서 PAGE_READ_BYTES 바이트를 읽음
        // 마지막 PAGE_ZERO_BYTES 바이트를 0으로 탈출
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        /* TODO: Set up aux to pass information to the lazy_load_segment. */
        // lazy_load_segment에 정보를 전달하도록 aux를 설정
        // aux 메모리 할당 
        // void *aux = NULL;
        struct load_aux *load_aux = (struct load_aux *)calloc(1, sizeof(struct load_aux));
        // aux 세팅       
        load_aux->page_read_bytes = read_bytes;
        load_aux->page_zero_bytes = zero_bytes;
        load_aux->file = open_file;
        load_aux->ofs = ofs;

        // 대기중인 오브젝트 생성 - 초기화되지 않은 주어진 타입의 페이지 생성
        if (!vm_alloc_page_with_initializer (VM_FILE, addr, writable, lazy_load_segment, load_aux)){
			free(addr);
            return NULL;
		}

        /* Advance. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        addr += PGSIZE;

        // 다음 파일을 위해 파일을 읽은 바이트만큼 오프셋 이동
        ofs += page_read_bytes;
    }

	// 가상주소 반환
    return return_addr;
}

/* Do the munmap */
// 지정된 주소 범위 addr에 대한 매핑을 해제
// 프로세스가 exit가 되면 모든 매핑이 암시적으로 해제되어야 함
// 그 후 해당 페이지는 프로세스의 가상 페이지 목록에서 제거되어야 함
void
do_munmap (void *addr) {
	struct thread *currnt = thread_current();

	// 반복문을 돌면서 모든 매핑을 해제
	while(true){
		struct page *page = spt_find_page(&currnt->spt, addr);

		if(page == NULL)
			return;

		// 파일이 수정된 경우 다시 수정할 수 있도록 aux를 받아옴
		struct load_aux *load_aux = (struct load_aux *)page->uninit.aux;

		// dirty bit(사용된 적이 있으면)가 1인 경우
		if(pml4_is_dirty(currnt->pml4, page->va)){
			// 수정된 파일을 다시 쓰기
			file_write_at(load_aux->file, addr,load_aux->page_read_bytes , load_aux->ofs);
			// 다시 dirty bit를 0으로 만들어줌
			pml4_set_dirty(currnt->pml4, page->va, 0);
		}

		// 현재 pml4로 매핑되어 있는 페이지를 삭제
		// process exit()에서 cleanup()을 호출하여 삭제하므로 여기서 페이지를 삭제하면 TC 실패
		// pml4_clear_page(currnt->pml4, page->va);

		// 다음으로 삭제할 페이지의 주소를 찾기 위해 삭제한 페이지의 크기만큼 addr 줄여주기
		addr += PGSIZE;
	}
}
/* ------------------------- project3-4_Memory Mapped Files ------------------------ */
