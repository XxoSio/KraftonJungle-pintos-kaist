/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"

/* ----------------------------------- project3-1_Memory Management ----------------------------------- */
#include "threads/vaddr.h"
#include "threads/mmu.h"

uint64_t spt_hash_hash_func (const struct hash_elem *e, void *aux);
bool spt_hash_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux);
/* ----------------------------------- project3-1_Memory Management ----------------------------------- */

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
// initializer를 사용하여 보류중인 페이지 객체를 만듦
// 직접 생성하지 말고 이 함수 또는 `vm_alloc_page` 사용
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	// user page의 사용여부 확인
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		// 페이지 생성 후, vm유형에 따라 초기화
		// uninit_new를 호출하여 uninit 페이지 구조 만들기
		// uninit_new를 호출한 뒤 필드 수정
		/* ----------------------------------- project3-1_Memory Management ----------------------------------- */
		struct page *page = (struct page *)malloc(sizeof(struct page));

		// writable 저장
		page->writable = writable;
		/* ----------------------------------- project3-1_Memory Management ----------------------------------- */

		/* TODO: Insert the page into the spt. */

	}
err:
	return false;
}

/* ----------------------------------- project3-1_Memory Management ----------------------------------- */
/* Find VA from spt and return page. On error, return NULL. */
// 보조 페이지 테이블에서 가상 주소(va)와 대응되는 페이지 구조체를 찾아서 반환
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function. */
	// 가장 가까운 페이지 경계 주소로 이동
	page->va = pg_round_down(va);

	// page 구조체 멤버 찾기
	struct hash_elem *check_page_hash_elem = hash_find(&spt->hash_table, &page->hash_elem);
	
	// 찾지 못한 경우 NULL 반환
	if(check_page_hash_elem == NULL)
		return NULL;
	// 찾은 경우 elem이 포함된 구조체에 대한 포인터를 반환
	else
		return hash_entry(check_page_hash_elem, struct page, hash_elem);
}

/* Insert PAGE into spt with validation. */
// 인자로 주어진 보조 페이지 테이블에 페이지 구조체를 삽입
// 주어진 보조 페이지 테이블에서 가상 주소가 존재하지 않는지 검사
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */
	// 삽입
	struct hash_elem *check_page_elem = hash_insert(&spt->hash_table, &page->hash_elem);

	if(check_page_elem == NULL)
		succ = true;
	else
		succ = false;

	return succ;
}
/* ----------------------------------- project3-1_Memory Management ----------------------------------- */

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* ----------------------------------- project3-1_Memory Management ----------------------------------- */
/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
// 프레임을 할당하고 멤버들을 초기화 한 후 프레임 반환
static struct frame *
vm_get_frame (void) {
	// struct frame *frame = NULL;
	
	/* TODO: Fill this function. */
	// 프레임 메모리 할당
	struct frame *frame = malloc(sizeof(struct frame));
	// user 메모리에서 물리 메모리 페이지 가져오기
	frame->kva = palloc_get_page(PAL_USER);
	// 프레임 페이지 초기화
	frame->page = NULL;

	ASSERT (frame != NULL);
	// ASSERT (frame->page == NULL);
	ASSERT (frame->kva != NULL);

	// 메모리를 성공적으로 가져온 경우
	if(frame->kva != NULL)
		return frame;
	// ! 가져오지 못한 경우 -> swap out
	// 일단 지금은 PANIC("todo")로 표시만 해둠
	else
		PANIC("todo");
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* ----------------------------------- project3-1_Memory Management ----------------------------------- */
/* Claim the page that allocate on VA. */
// 인자로 주어진 va에 페이지 할당 -> 해당 페이지에 프레임 할당
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */
	struct thread *current = thread_current();
	// spt에서 할당할 페이지의 va 찾아 정보 가져오기
	page = spt_find_page(&current->spt, va);

	// 정보를 얻지못한 경우 false 반환
	if(page == NULL)
		return false;

	// 성공한 경우 vm_do_claim_page() 함수 호출
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
// 페이지를 할당하고 mmu를 설정
// mmu : 가상 주소와 물리 주소를 매핑한 정보를 페이지 테이블에 추가해야 하는 것
static bool
vm_do_claim_page (struct page *page) {
	ASSERT (page != NULL);

	struct frame *frame = vm_get_frame ();
	struct thread * current = thread_current();

	/* Set links */
	ASSERT (frame != NULL);
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	// 페이지의 VA를 프레임의 PA에 매핑할 페이지 테이블 항목 삽입
	if(!pml4_set_page(current->pml4, page->va, frame->kva, page->writable))
		return false;
	else
		return swap_in (page, frame->kva);
}

/* Computes and returns the hash value for hash element E, given
 * auxiliary data AUX. */
// 주어진 보조 데이터 aux에서 해시 요소 E의 해시값을 계산하고 반환
uint64_t
page_hash (const struct hash_elem *e, void *aux){
	const struct page *p = hash_entry (e, struct page, hash_elem);
	
  	return hash_bytes (&p->va, sizeof p->va);
}

/* Compares the value of two hash elements A and B, given
 * auxiliary data AUX.  Returns true if A is less than B, or
 * false if A is greater than or equal to B. */
// addr을 키로 사용하여 해시 함수와 비교 함수를 작성함
// 주어진 보조 데이터 aux가 주어지면 두 해시 요소 A와 B의 값을 비교 
bool
page_less (const struct hash_elem *a, const struct hash_elem *b, void *aux){
  const struct page *ap = hash_entry (a, struct page, hash_elem);
  const struct page *bp = hash_entry (b, struct page, hash_elem);

  return ap->va < bp->va;
}

/* Initialize new supplemental page table */
// 새 보조 페이지 테이블 초기화
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&spt->hash_table, page_hash, page_less, NULL);
}
/* ----------------------------------- project3-1_Memory Management ----------------------------------- */

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
}
