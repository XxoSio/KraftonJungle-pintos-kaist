/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"

// /* ----------------------------------- project3-1_Memory Management ----------------------------------- */
// #include "lib/kernel/hash.h"
// #include "threads/vaddr.h"
// #include "threads/mmu.h"
// /* ----------------------------------- project3-1_Memory Management ----------------------------------- */

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
// 초기화되지 않은 주어진 타입의 페이지 생성
// initializer를 사용하여 보류중인 페이지 객체를 만듦
// 초기화되지 않은 페이지의 swap_in 핸들러는 자동적으로 페이지 타입에 맞게 페이지를 초기화하고 주어진 AUX를 인자로 삼는 INIT 함수를 호출
// vm.h에 정의되어 있는 VM_TYPE 매크로를 사용하면 편리
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable, vm_initializer *init, void *aux) {

	// 에러 체크 - VM_TYPE이 VM_UNINIT인 경우 에러
	ASSERT (VM_TYPE(type) != VM_UNINIT)

	// 현재 스레드의 보조 페이지 테이블 가져오기
	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	// spt_find_page()를 호출하여 upage가 이미 할당 중인지 확인
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		// 페이지 생성 후, vm유형에 따라 초기화
        // uninit_new를 호출하여 uninit 페이지 구조 만들기
        // uninit_new를 호출한 뒤 필드 수정
        
    	/* ------------------------- project3-2-1_Anonymous Page_Lazy Loading for Executable ------------------------ */
		// 페이지 메모리 할당
		struct page *page = (struct page *)calloc(1, sizeof(struct page));

		typedef bool(*page_initializer)(struct page *, enum vm_type, void *);
		page_initializer initializer = NULL;

		// 타입 확인
		switch (type)
		{
			case VM_ANON:
				// VM_ANON 타입에 맞게 초기화 함수 넣기
				initializer = anon_initializer;
				break;
			case VM_FILE:
				// VM_FILE 타입에 맞게 초기화 함수 넣기
				initializer = file_backed_initializer;
				break;
		}
		// uninit_new를 호출하여 uninit 페이지 구조 만들기
		uninit_new(page, upage, init, type, aux, initializer);

		/* ----------------------------------- project3-1_Memory Management ----------------------------------- */
		// writable 저장
		page->writable = writable;
		/* ----------------------------------- project3-1_Memory Management ----------------------------------- */

		// 스택인 경우 구분
		if (type == VM_STACK)
			page->stack = true;

		/* TODO: Insert the page into the spt. */
		// 보조 페이지 테이블에 페이지 삽입
		return spt_insert_page(spt, page);
		/* ------------------------- project3-2-1_Anonymous Page_Lazy Loading for Executable ------------------------ */
	}
err:
	return false;
}

/* ----------------------------------- project3-1_Memory Management ----------------------------------- */
/* Find VA from spt and return page. On error, return NULL. */
// 보조 페이지 테이블에서 가상 주소(va)와 대응되는 페이지 구조체를 찾아서 반환
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	/* TODO: Fill this function. */
	struct page *page = (struct page *)calloc(1, sizeof(struct page));
	struct hash_elem *hash_elem;

	// pg_round_down()를 사용해 가장 가까운 페이지 경계 주소 찾기
	// -> va가 가리키는 가상 페이지의 시작 포인트(오프셋이 0으로 설정된 va) 반환
	page->va = pg_round_down(va);

	// hash_find()를 사용해 보조 테이블에서 hash_elem 구조체 찾기
	hash_elem = hash_find(&spt->hash_table, &page->hash_elem);
	
	// 에러 체크 - hash_elem가 비어있는 경우
	if (hash_elem == NULL) {
		// NULL 리턴
		return NULL;
	}
	// hash_elem가 비어있지 않은 경우
	else{
		// hash_elem이 소속되어있는 구조체의 포인터를 반환
		return hash_entry(hash_elem, struct page, hash_elem);
	}
}

/* Insert PAGE into spt with validation. */
// 인자로 주어진 보조 페이지 테이블에 페이지 구조체를 삽입
// 주어진 보조 페이지 테이블에서 가상 주소가 존재하지 않는지 검사
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED, struct page *page UNUSED) {
	int succ = false;
	
	/* TODO: Fill this function. */
	// hash_find()를 사용해 hash_elem 구조체 찾기
	struct hash_elem *check_page_elem = hash_find(&spt->hash_table, &page->hash_elem);

	// 에러 체크 - check_page_elem이 NULL인 경우
	if(check_page_elem != NULL)
		// false 반환
		return succ;
	// check_page_elem가 비어있지 않은 경우
	else{
		// hash_insert()를 사용하여 보조 테이블에 hash_elem 넣기
		hash_insert(&spt->hash_table, &page->hash_elem);
		// 성공한 경우 succ값 true로 변환후 반환
 		succ = true;
		return succ;
	}
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
	struct frame *frame = NULL;

	/* TODO: Fill this function. */
	// frame 메모리 할당
	frame = (struct frame *)calloc(1, sizeof(struct frame));

	// palloc_get_page()를 사용하여
	// 4kb만큼 물리 메모리 공간을 잡고 물리 메모리의 시작 주소 리턴 받아 저장
	frame->kva = palloc_get_page(PAL_USER);

	// 에러 체크
	// - 프레임이 NULL인 경우
	// - 프레임의 페이지가 NULL이 아닌 경우
	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);

	// 페이지 할당에 실패한 경우 - 메모리의 시작 주소가 NULL인 경우
	// swap out을 할 필요가 없음 - 일단은 PANIC("todo")으로 표시
	if (frame->kva == NULL)
		PANIC("todo");
	// 페이지 할당에 성공한 경우
	else
		// 해단 프레임 반환
		return frame;
}
/* ----------------------------------- project3-1_Memory Management ----------------------------------- */

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* ------------------------- project3-2-1_Anonymous Page_Lazy Loading for Executable ------------------------ */
/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED, bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	// 현재 스레드의 보조 페이지 테이블 가져오기
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;

	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	// 페이지 폴트 확인 - 유효한 값인지
	if(is_kernel_vaddr(addr))
		return false;

	// 현재 페이지가 없는 경우
	if (not_present) {
		// 보조 페이지 테이블에서 주소에 맞는 페이지 가져오기
        page = spt_find_page(spt, addr);

		// 가져온 페이지가 NULL인 경우
        if (page == NULL)
			// false 리턴
            return false;

		// 페이지에 프레임을 할당하고 mmu 설정
        if (vm_do_claim_page (page) == false)
			// 실패한 경우 false 리턴
            return false;
    }

	// 성공한 경우 true 리턴
	return true;
}
/* ------------------------- project3-2-1_Anonymous Page_Lazy Loading for Executable ------------------------ */

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* ----------------------------------- project3-1_Memory Management ----------------------------------- */
/* Claim the page that allocate on VA. */
// 인자로 주어진 va에 페이지를 할당하고, 해당 페이지에 프레임 할당
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;

	/* TODO: Fill this function */

	// 에러 체크 - va가 사용자 영역이 아닌 경우
	ASSERT(is_user_vaddr(va));

	// 현재 스레드 받아오기
	struct thread *current = thread_current();
	// 현재 스레드 보조 페이지 테이블의 va 위치에 있는 페이지 찾기
	page = spt_find_page(&current->spt, va);

	// 페이지가 NULL인 경우
	if (page == NULL)
		// flase 리턴
		return false;
	// 페이지를 성공적으로 가져온 경우
	else
		// 찾은 페이지를 인자로 하여 vm_do_claim_page() 리턴
		// - 페이지에 프레임 할당 & mmu설정
		return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
// 페이지에 물리 메모리 프레임을 할당하고 mmu를 설정
// mmu : 가상 주소와 물리 주소를 매핑한 정보를 페이지 테이블에 추가해야 하는 것
static bool
vm_do_claim_page (struct page *page) {
	ASSERT (page != NULL);

	// vm_get_frame()를 사용하여 프레임 할당받기
	struct frame *frame = vm_get_frame ();
	// 프레임을 할당할 스레드 받아오기
	struct thread *current = thread_current();

	// 에러 체크 - 프레임이 NULL인 경우
	ASSERT (frame != NULL);

	// 프레임과 페이지 링크
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	// 페이지의 VA를 프레임의 PA에 매핑할 페이지 테이블 항목 삽입
	// pml4_get_page()
	// -> pml4에서 사용자 가상 주소(UADDR)에 해당하는 물리적 주소를 검색
	// pml4_set_page()
	// -> 사용자 가상 페이지(UPAGE)에서 커널 가상 주소(KPAGE)로 식별된 물리적 프레임으로 페이지 맵 레벨 4(PML4)의 매핑을 추가
	if(pml4_get_page(current->pml4, page->va) == NULL && pml4_set_page(current->pml4, page->va, frame->kva, page->writable)){
		// stack의 경우 swap_in 과정이 진행되지 않아도 됨
		if(page->stack == true)
			return true;
		else
			// 페이지 구조체 안의 page_operations 구조체를 통해 swap_int 함수 테이블에 값 넣기
			return swap_in (page, frame->kva);
	}
	// 삽입에 실패한 경우
	else
		// false 리턴
		return false;
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
