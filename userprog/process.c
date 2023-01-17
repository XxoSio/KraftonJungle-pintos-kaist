#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);

/* General process initializer for initd and other process. */
static void
process_init (void) {
    struct thread *current = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
    char *fn_copy, *save_ptr;
    tid_t tid;

    /* Make a copy of FILE_NAME.
     * Otherwise there's a race between the caller and load(). */
    fn_copy = palloc_get_page (0);
    if (fn_copy == NULL)
        return TID_ERROR;
    strlcpy (fn_copy, file_name, PGSIZE);

    /* ----------------------------------- project2-1_Argument Passing ----------------------------------- */
    // 첫번째 토큰을 이름으로 전달
    // 첫번째 공백 전까지 문자열 파싱
    strtok_r(file_name, " ", &save_ptr);
    /* ----------------------------------- project2-1_Argument Passing ----------------------------------- */

    /* Create a new thread to execute FILE_NAME. */
    tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);
    if (tid == TID_ERROR)
        palloc_free_page (fn_copy);
    return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
    supplemental_page_table_init (&thread_current ()->spt);
#endif

    process_init ();

    if (process_exec (f_name) < 0)
        PANIC("Fail to launch initd\n");
    NOT_REACHED ();
}

/* -------------- project2-3-2_System calls-Process ------------- */
// 자식 리스트를 pid로 검색하여 해당 프로세스 디스크립터를 반환
// 자식 리스트에 찾는 tid가 없을 경우 NULL 반환
struct
thread *get_child_process(int tid) {
    struct thread *current = thread_current();
    struct list *child_list = &current->child_list;

    // 순회를 돌면서 검사를 해주어야 하므로 list_begin()으로 시작 위치 받아오기
    struct list_elem *el = list_begin(child_list);
    // 자식 리스트의 마지막까지 반복
    while(el != list_end(child_list)) {
        // 자식 리스트에서 thread 받아오기
        struct thread *th = list_entry(el, struct thread, child_elem);
        // 받아온 thread의 tid가 찾는 tid와 일치하는 경우
        // 해당 tid 반환
        if(th->tid == tid) {
            return th;
        }
        // 다음 자식으로 넘기기 위해 list_next() 사용
        el = list_next(el);
    }

    // tid를 찾지 못하면 NULL 반환
    return NULL;
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
// thread_name으로 현재 스레드 복제하고, 새로운 스레드의 tid를 반환
// 복제할 부모 프로세스의 이름과 레지스터에 작업하던 context 정보(intr_frame)를 받아 자식 프로세스로 복제
// 부모 스레드 : 현재 실행중인 사용자 스레드
// 현재 시스템 콜로 intr_frame 값을 바꾼 상태 -> tf.rsp는 사용자 스택에서 커널 스택으로 변경됨
// 스레드 이름과 부모 스레드를 이용하여 __do_fork()를 실행해야 함 -> 사용자 스택의 정보를 인터럽트 프레임 안에 넣어 넘겨야함
// 이를 위해 부모 스레드에 child_if라는 인터럽트 프레임을 만들고, 넘겨주자! -> thread 구조체에 추가
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED) {
    /* Clone current thread to new thread.*/
    // 기존 코드
    // return thread_create (name,
    //      PRI_DEFAULT, __do_fork, thread_current ());

    struct thread *parent = thread_current();
    // 전달받은 부모 intr_frame을 현재 스레드의 parent_if에 복사
    memcpy(&parent->child_if, if_, sizeof(struct intr_frame));
    
    // 전달받은 thread_name으로 __do_fork() 실행
    // 현재 스레드를 인자로 넘겨줌
    tid_t tid = thread_create(name, PRI_DEFAULT, __do_fork, parent);
    // 스레드 생성에 실패한 경우 TIP ERROR 반환
    if(tid == TID_ERROR) {
        return TID_ERROR;
    }

    // 복제한 자식 스레드의 tid를 검색하여 정보를 받아옴
    struct thread *child = get_child_process(tid);

    // 자식 스레드의 load가 끝날때까지 대기
    sema_down(&child->fork_sys_sema);
    // 자식 프로세스가 비정상적 종료(-1)를 하면 에러 반환
    if (child->exit_status == -1) {
        return TID_ERROR;
    }

    // 복제가 완료되면 복제된 스레드의 tid 반환
    return tid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
// 부모의 페이지 테이블을 복제하기 위해 페이지 테이블 생성
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
    struct thread *current = thread_current ();
    struct thread *parent = (struct thread *) aux;
    void *parent_page;
    void *newpage;
    bool writable;

    /* 1. TODO: If the parent_page is kernel page, then return immediately. */
    // 부모의 페이지가 커널 페이지인 경우, 즉시 false 리턴
    if(is_kernel_vaddr(va))
        return true;

    /* 2. Resolve VA from the parent's page map level 4. */
    // 부모 스레드 내 멤버인 pml4를 이용해 부모 페이지를 불러옴
    parent_page = pml4_get_page (parent->pml4, va);
    if(parent_page == NULL)
        return false;

    /* 3. TODO: Allocate new PAL_USER page for the child and set result to
     *    TODO: NEWPAGE. */
    // 새로운 PAL_USER 페이지를 할당하고, newpage에 저장
    newpage = palloc_get_page(PAL_USER);
    if(newpage == NULL)
        return false;

    /* 4. TODO: Duplicate parent's page to the new page and
     *    TODO: check whether parent's page is writable or not (set WRITABLE
     *    TODO: according to the result). */
    // 부모 페이지를 복사해 3에서 할당받은 페이지에 넣어줌
    // 이때 부모 페이지가 WRITABLE인지 아닌지 확인하기 위해 is_writable() 함수 이용
    memcpy(newpage, parent_page, PGSIZE);
    writable = is_writable(pte);

    /* 5. Add new page to child's page table at address VA with WRITABLE
     *    permission. */
    // 쓰기 가능 권한이 있는 주소 VA의 하위 페이지 테이블에 새 페이지를 추가
    if (!pml4_set_page (current->pml4, va, newpage, writable)) {
        /* 6. TODO: if fail to insert page, do error handling. */
        // 페이지 생성에 실패하면 에러 핸들링이 동작하도록 false 반환
        return false;
    }

    // 모든 과정이 잘 되었으면 true를 반환
    return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
// 부모의 context 정보를 복사하는 함수
static void
__do_fork (void *aux) {
    struct intr_frame if_;
    struct thread *parent = (struct thread *) aux;
    struct thread *child = thread_current ();
    /* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
    // 기존 코드
    // 스레드 구조체에 선언해주었으므로 필요 없음
    // struct intr_frame *parent_if;
    bool succ = true;

    /* 1. Read the cpu context to local stack. */
    // 기존 코드
    // memcpy (&if_, parent_if, sizeof (struct intr_frame));
    // 부모 스레드의 기본 인터럽트 프레임인 tf가 아닌, fork()에서 복사해준
    // child_if를 복사해야함
    memcpy (&if_, &parent->child_if, sizeof (struct intr_frame));

    /* 2. Duplicate PT */
    child->pml4 = pml4_create();
    if (child->pml4 == NULL)
        goto error;

    process_activate (child);
#ifdef VM
    supplemental_page_table_init (&child->spt);
    if (!supplemental_page_table_copy (&child->spt, &parent->spt))
        goto error;
#else
    if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
        goto error;
#endif

    /* TODO: Your code goes here.
     * TODO: Hint) To duplicate the file object, use `file_duplicate`
     * TODO:       in include/filesys/file.h. Note that parent should not return
     * TODO:       from the fork() until this function successfully duplicates
     * TODO:       the resources of parent.*/
    // 힌트) 파일 개체를 복제하려면 include/filesys/file.h에서 'file_duplicate'를 사용
    // 이 함수가 부모의 리소스를 성공적으로 복제할 때까지 부모는 포크()에서 돌아오지 않아야함

    // 파일 디스크립터 테이블에 스레드를 더 이상 추가될 수 없는 경우 error 처리
    if(parent->file_descriptor_index == FDT_LIMIT)
        goto error;
    
    // 자식 스레드의 파일 페이지는 부모의 파일 페이지의 context 정보와 동일하게 해줘야함
    // stdin, stdout은 그냥 바로 매칭해주자
    child->file_descriptor_talbe[0] = parent->file_descriptor_talbe[0];
    child->file_descriptor_talbe[1] = parent->file_descriptor_talbe[1];

    // 파일 디스크립터 테이블을 돌면서 정보 저장
    for(int i = 2; i < FDT_LIMIT; i++){
        // i번째 인덱스에 있는 context 정보 받아오기
        struct file *f = parent->file_descriptor_talbe[i];

        // 받아온 파일 정보가 NULL인 경우
        // 해당 인덱스에는 파일이 없다는 뜻이므로 복사를 하지않고 넘어감
        if (f == NULL)
            continue;

        // 부모의 파일 디스크립터 페이지 배열로부터 값을 하나씩 붙여넣음
        // file_duplicate()함수 사용
        child->file_descriptor_talbe[i] = file_duplicate(f);
    }

    // 자식의 인덱스의 값도 부모와 동일하게 저장
    child->file_descriptor_index = parent->file_descriptor_index;
    // fork()함수의 결과로 자식 프로세스는 0을 반환
    // if_.R.rax를 0으로 만들자
    if_.R.rax = 0;
    // fork()가 잘 되었으니, sema_up()을 해주어 load가 잘 되었음을 부모에게 알림
    sema_up(&child->fork_sys_sema);
    
    // 기존 코드
    // process_init ();

    /* Finally, switch to the newly created process. */
    if (succ)
        do_iret (&if_);

// 에러가 발생한 경우(goto error) 처리해줄 코드들
error:
    //기존 코드
    // thread_exit ();

    // 자식의 종료 상태를 에러로 변경
    child->exit_status = TID_ERROR;
    // sema_down을 하고 들어오는 함수이므로 sema_up을 해주어야 함
    sema_up(&child->fork_sys_sema);
    // 에러 코드로 종료
    exit(TID_ERROR);
}
/* -------------- project2-3-2_System calls-Process ------------- */

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
// 유저가 입력한 명령어를 수행하도록 프로그램을 메모리에 적재하고 실행하는 함수
// 여기에 파일을 네임 인자로 받아서 저장(문자열)
int
process_exec (void *f_name) {
    // f_name은 문자열이지만 void*로 넘겨받음
    // 이를 문자열로 인식하기 위해 char*로 변환
    char *file_name = f_name;
    bool success;

    /* We cannot use the intr_frame in the thread structure.
     * This is because when current thread rescheduled,
     * it stores the execution information to the member. */
    // intr_frame내 구조체 멤버에 필요한 정보를 담아둠
    struct intr_frame _if;
    _if.ds = _if.es = _if.ss = SEL_UDSEG;
    _if.cs = SEL_UCSEG;
    _if.eflags = FLAG_IF | FLAG_MBS;

    /* We first kill the current context */
    // 새로운 실행 파일을 현재 스레드에 담기 전에
    // 현재 프로세스에 담긴 context를 지워줌
    // 지워준다는 것은 프로세스에 할당된 page directory를 지운다는 것
    process_cleanup ();

	/* ----------------------------------- project3_Clean up code ----------------------------------- */
	// 초기화를 해주고 바로 cleanup을 해주면서 supplemental_page_table_kill()을 불러옴
	// 해당 함수를 안쓰면 supplemental_page_table_kill()에서 hash_clear()만 사용하여 free를 못해줌
	// supplemental_page_table_kill()에서 hash_destroy()를 사용하여 free를 해주면서 메모리를 잡아야함
	// 따라서 메모리 누수를 잡으면서 kill을 해주기 위해 다시 초기화 해주는 함수를 추가
	supplemental_page_table_init(&thread_current()->spt);
	/* ----------------------------------- project3_Clean up code ----------------------------------- */

    /* ----------------------------------- project2-1_Argument Passing ----------------------------------- */
    /* And then load the binary */
    // _if(intr_frame)와 file_name을 현재 프로세스에 load
    // 만약 load에 성공하면 1을 반환하고, 아니면 0을 반환
    // 물론 file_name의 첫번째 문자열을 parsing해서 넘겨줘야 함
    // load안에서 argument_stack을 해줌
    success = load (file_name, &_if);
    /* ----------------------------------- project2-1_Argument Passing ----------------------------------- */

    /* If load failed, quit. */
    // file_name은 우리가 프로그램 파일 이름을 받기 위해 만든 임시 변수
    // 따라서 load가 끝났다면, 해당 메모리 반환
    palloc_free_page (file_name);
    
    // load가 실패했다면 -1을 반환
    if (!success)
        return -1;

    /* ----------------------------------- project2-1_Argument Passing ----------------------------------- */
    // pintos에서 제공하는 디버깅 툴
    // make check할때는 값을 지워야함
    // 메모리 내용을 16진수로 화면에 출력
    // 유저 스택에 인자를 저장 후 사용자 스택 메모리 확인
    // USER_STACK - _if.rsp : 사용자 스택 메모리만 사용해야하므로 해당 값을 구해줌
    // rsp : 스택의 시작 주소
    // hex_dump(_if.rsp, _if.rsp, USER_STACK - _if.rsp, true);
    /* ----------------------------------- project2-1_Argument Passing ----------------------------------- */

    /* Start switched process. */
    // 만약 load가 실행했다면, context switching을 실행
    do_iret (&_if);
    NOT_REACHED ();
}


/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
// 자식 프로세스 pid를 기다리고 자식의 종료 상태를 검색
int
process_wait (tid_t child_tid UNUSED) {
    /* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
     * XXX:       to add infinite loop here before
     * XXX:       implementing the process_wait. */
    /* ----------------------------------- project2-1_Argument Passing ----------------------------------- */
    // system call을 기다려야함
    // 구현이 안됐으니 일단 무한 루프
    // for(int i = 0 ; i < 1000000000; i++){}
    /* ----------------------------------- project2-1_Argument Passing ----------------------------------- */

    // 기존 코드
    // return -1;

    /* -------------- project2-3-2_System calls-Process ------------- */
    // 자식 리스트를 tid로 검색하여 해당 프로세스 디스크립터를 반환
    struct thread *child = get_child_process(child_tid);

    // 반환받은 디스크립터가 없다면 -1 리턴
    if (child == NULL)
        return -1;
    // 정상적으로 디스크립터를 반환받은 경우
    else{
        // 자식 프로세스가 종료할때 까지 대기
        sema_down(&child->wait_sys_sema);
        
        // 자식으로부터 종료인자를 전달 받고 리스트에서 삭제
        int exit_status = child->exit_status;
        list_remove(&child->child_elem);

        // 자식 프로세스 종료 상태인자 받은 후 자식 프로세스 종료하게 함
        sema_up(&child->exit_sys_sema);

        // 종료 상태를 리턴
        return exit_status;
    }
    /* -------------- project2-3-2_System calls-Process ------------- */
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
    struct thread *curr = thread_current ();
    /* TODO: Your code goes here.
     * TODO: Implement process termination message (see
     * TODO: project2/process_termination.html).
     * TODO: We recommend you to implement process resource cleanup here. */

    /* -------------- project2-3-2_System calls-Process ------------- */
    // 파일 디스크립터 테이블을 돌면서 열려있는 파일을 모두 닫음
    for(int i = 0; i < FDT_LIMIT; i++)
        close(i);

    // 현재 프로세스가 실행중인 파일 종료
    file_close(curr->running_file);
    // thread_create에서 할당한 페이지 할당 해제
    palloc_free_multiple(curr->file_descriptor_talbe, 3);
    /* -------------- project2-3-2_System calls-Process ------------- */

    // 현재 프로세스의 자원 반납
    process_cleanup ();
    
    /* -------------- project2-3-2_System calls-Process ------------- */
    // 부모 프로세스가 자식 프로세스의 종료상태 확인하게 함
    sema_up(&curr->wait_sys_sema);
    // 부모 프로세스가 자식 프로세스 종료인자 받을때 까지 대기
    sema_down(&curr->exit_sys_sema);
    /* -------------- project2-3-2_System calls-Process ------------- */
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
    struct thread *curr = thread_current ();

#ifdef VM
    supplemental_page_table_kill (&curr->spt);
#endif

    uint64_t *pml4;
    /* Destroy the current process's page directory and switch back
     * to the kernel-only page directory. */
    pml4 = curr->pml4;
    if (pml4 != NULL) {
        /* Correct ordering here is crucial.  We must set
         * cur->pagedir to NULL before switching page directories,
         * so that a timer interrupt can't switch back to the
         * process page directory.  We must activate the base page
         * directory before destroying the process's page
         * directory, or our active page directory will be one
         * that's been freed (and cleared). */
        curr->pml4 = NULL;
        pml4_activate (NULL);
        pml4_destroy (pml4);
    }
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
    /* Activate thread's page tables. */
    pml4_activate (next->pml4);

    /* Set thread's kernel stack for use in processing interrupts. */
    tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
    unsigned char e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct ELF64_PHDR {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
        uint32_t read_bytes, uint32_t zero_bytes,
        bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) {
    struct thread *t = thread_current ();
    struct ELF ehdr;
    struct file *file = NULL;
    off_t file_ofs;
    bool success = false;
    int i;

    /* ----------------------------------- project2-1_Argument Passing ----------------------------------- */
    // argument_stack을 부르기 위한 작업
    // strtok_r로 인자들을 공백 기준으로 잘라 각 주소에 넣음
    // 커맨드 라인 길이 제한 128
    char *parse[128];
    char *token, *save_ptr;
    int count = 0;

    for (token = strtok_r (file_name, " ", &save_ptr); token != NULL; token = strtok_r (NULL, " ", &save_ptr))
        parse[count++] = token;
    /* ----------------------------------- project2-1_Argument Passing ----------------------------------- */

    /* Allocate and activate page directory. */
    t->pml4 = pml4_create ();
    if (t->pml4 == NULL)
        goto done;
    process_activate (thread_current ());

    /* Open executable file. */
    file = filesys_open (file_name);
    if (file == NULL) {
        printf ("load: %s: open failed\n", file_name);
        goto done;
    }

    /* -------------- project2-3-2_System calls-Process ------------- */
    // 실행중인 파일 저장
    t->running_file = file;
    // 실행중인 파일을 수정하려고 하는 것을 방지
    file_deny_write(file);
    /* -------------- project2-3-2_System calls-Process ------------- */

    /* Read and verify executable header. */
    if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
            || memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
            || ehdr.e_type != 2
            || ehdr.e_machine != 0x3E // amd64
            || ehdr.e_version != 1
            || ehdr.e_phentsize != sizeof (struct Phdr)
            || ehdr.e_phnum > 1024) {
        printf ("load: %s: error loading executable\n", file_name);
        goto done;
    }

    /* Read program headers. */
    file_ofs = ehdr.e_phoff;
    for (i = 0; i < ehdr.e_phnum; i++) {
        struct Phdr phdr;

        if (file_ofs < 0 || file_ofs > file_length (file))
            goto done;
        file_seek (file, file_ofs);

        if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
            goto done;
        file_ofs += sizeof phdr;
        switch (phdr.p_type) {
            case PT_NULL:
            case PT_NOTE:
            case PT_PHDR:
            case PT_STACK:
            default:
                /* Ignore this segment. */
                break;
            case PT_DYNAMIC:
            case PT_INTERP:
            case PT_SHLIB:
                goto done;
            case PT_LOAD:
                if (validate_segment (&phdr, file)) {
                    bool writable = (phdr.p_flags & PF_W) != 0;
                    uint64_t file_page = phdr.p_offset & ~PGMASK;
                    uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
                    uint64_t page_offset = phdr.p_vaddr & PGMASK;
                    uint32_t read_bytes, zero_bytes;
                    if (phdr.p_filesz > 0) {
                        /* Normal segment.
                         * Read initial part from disk and zero the rest. */
                        read_bytes = page_offset + phdr.p_filesz;
                        zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                    } else {
                        /* Entirely zero.
                         * Don't read anything from disk. */
                        read_bytes = 0;
                        zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                    }
                    if (!load_segment (file, file_page, (void *) mem_page,
                                read_bytes, zero_bytes, writable))
                        goto done;
                }
                else
                    goto done;
                break;
        }
    }

    /* Set up stack. */
    if (!setup_stack (if_))
        goto done;

    /* Start address. */
    if_->rip = ehdr.e_entry;

    /* TODO: Your code goes here.
     * TODO: Implement argument passing (see project2/argument_passing.html). */
    /* ----------------------------------- project2-1_Argument Passing ----------------------------------- */
    argument_stack(parse, count, if_);
    /* ----------------------------------- project2-1_Argument Passing ----------------------------------- */

    success = true;

done:
    /* We arrive here whether the load is successful or not. */

    /* -------------- project2-3-2_System calls-Process ------------- */
    // 해당 부분을 반드시 주석처리 해주어야함
    // load에서 file_close를 해버리면 file이 닫히면서 lock을 해제하게 됨
    // 따라서 load에서 file_close를 하는 것이 아니라
    // 실제 파일을 닫아야하는 함수인 process_exit()에서 닫자
    // file_close (file);
    /* -------------- project2-3-2_System calls-Process ------------- */

    return success;
}

/* ----------------------------------- project2-1_Argument Passing ----------------------------------- */
// 스택에 프로그램명, 함수 인자 저장
// 프로그램 이름 및 인자(문자열) push
// 프로그램 이름 및 인자 주소들 push
// argv(문자열을 가리키는 주소들의 배열을 가리킴) push
// argc(문자열의 개수 저장) push
// fake adress(0) 저장
void
argument_stack(char **parse, int count, struct intr_frame *if_)
{
    // 스택에 담을 각 인자의 주소값을 저장
    char *parse_address[128];

    // 거꾸로 삽입 -> 스택은 반대 방향으로 확장하기 때문
    // 맨 끝 NULL 값(arg[4]) 제외하고 스택에 저장(arg[3]~arg[0])
    for (int i = count - 1; i >= 0; i--)
    {
        // foo 면 3
        int parse_len = strlen(parse[i]);
        // if_->rsp: 현재 user stack에서 현재 위치를 가리키는 스택 포인터
        // 각 인자에서 인자 크기(argv_len)를 읽고 
        // (이때 각 인자에 sentinel이 포함되어 있으니, +1 -> strlen에서는 sentinel 빼고 읽음)
        // 그 크기만큼 rsp를 내려줌. 그 다음 빈 공간만큼 memcpy를 해줌
        if_->rsp = if_->rsp - (parse_len + 1);
        memcpy(if_->rsp, parse[i], parse_len + 1);
        // arg_address 배열에 현재 문자열 시작 주소 위치를 저장
        parse_address[i] = if_->rsp;
    }

    // word-align: 8의 배수 맞추기 위해 padding 삽입
    while (if_->rsp % 8 != 0)
    {
        // 주소값을 1 내리고
        if_->rsp--;
        //데이터에 0 삽입 => 8바이트 저장
        *(uint8_t *)if_->rsp = 0;
    }

    // 이제는 주소값 자체를 삽입
    // char 포인터 크기: 8바이트
    // 8바이트만큼 내리고
    if_->rsp = if_->rsp - 8;
    // 가장 위에는 0을 넣음
    memset(if_->rsp, 0, sizeof(char **));

    for (int i = count - 1; i >= 0; i--)
    {
        if_->rsp = if_->rsp - 8;
        // 나머지에는 arg_address 안에 들어있는 값 가져오기
        memcpy(if_->rsp, &parse_address[i], sizeof(char **));
    }

    if_->R.rdi = count;
    // arg_address 맨 앞 가리키는 주소값
    if_->R.rsi = if_->rsp;

    // fake return address
    // void 포인터도 8바이트 크기
    if_->rsp = if_->rsp - 8;
    memset(if_->rsp, 0, sizeof(void *));
}
/* ----------------------------------- project2-1_Argument Passing ----------------------------------- */


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
    /* p_offset and p_vaddr must have the same page offset. */
    if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
        return false;

    /* p_offset must point within FILE. */
    if (phdr->p_offset > (uint64_t) file_length (file))
        return false;

    /* p_memsz must be at least as big as p_filesz. */
    if (phdr->p_memsz < phdr->p_filesz)
        return false;

    /* The segment must not be empty. */
    if (phdr->p_memsz == 0)
        return false;

    /* The virtual memory region must both start and end within the
       user address space range. */
    if (!is_user_vaddr ((void *) phdr->p_vaddr))
        return false;
    if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
        return false;

    /* The region cannot "wrap around" across the kernel virtual
       address space. */
    if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
        return false;

    /* Disallow mapping page 0.
       Not only is it a bad idea to map page 0, but if we allowed
       it then user code that passed a null pointer to system calls
       could quite likely panic the kernel by way of null pointer
       assertions in memcpy(), etc. */
    if (phdr->p_vaddr < PGSIZE)
        return false;

    /* It's okay. */
    return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
        uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
    ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT (pg_ofs (upage) == 0);
    ASSERT (ofs % PGSIZE == 0);

    file_seek (file, ofs);
    while (read_bytes > 0 || zero_bytes > 0) {
        /* Do calculate how to fill this page.
         * We will read PAGE_READ_BYTES bytes from FILE
         * and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        /* Get a page of memory. */
        uint8_t *kpage = palloc_get_page (PAL_USER);
        if (kpage == NULL)
            return false;

        /* Load this page. */
        if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
            palloc_free_page (kpage);
            return false;
        }
        memset (kpage + page_read_bytes, 0, page_zero_bytes);

        /* Add the page to the process's address space. */
        if (!install_page (upage, kpage, writable)) {
            printf("fail\n");
            palloc_free_page (kpage);
            return false;
        }

        /* Advance. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
    }
    return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
    uint8_t *kpage;
    bool success = false;

    kpage = palloc_get_page (PAL_USER | PAL_ZERO);
    if (kpage != NULL) {
        success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
        if (success)
            if_->rsp = USER_STACK;
        else
            palloc_free_page (kpage);
    }
    return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
    struct thread *t = thread_current ();

    /* Verify that there's not already a page at that virtual
     * address, then map our page there. */
    return (pml4_get_page (t->pml4, upage) == NULL
            && pml4_set_page (t->pml4, upage, kpage, writable));
}
#else

/* ------------------------- project3-2-1_Anonymous Page_Lazy Loading for Executable ------------------------ */
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */
// 실행 가능한 파일의 페이지들을 초기화하는 함수이고 page fault가 발생할 때 호출
// 페이지 구조체와 aux를 인자로 받음
// aux는 load_segment에서 설정하는 정보
/* ----------------------------------- project3-4_Memory Mapped Files ----------------------------------- */
// 파일 메모리 매핑때 재사용을 위해 선언
bool
/* ----------------------------------- project3-4_Memory Mapped Files ----------------------------------- */
lazy_load_segment (struct page *page, void *aux) {
    /* TODO: Load the segment from the file */
    /* TODO: This called when the first page fault occurs on address VA. */
    /* TODO: VA is available when calling this function. */
    // 파일 세그먼트를 로드
    // aux 정보를 사용하여 읽을 파일을 찾고, 최종적으로 세그먼트를 메모리에서 읽어야 함
    // 첫번째 페이지 오류가 발생할 때 호출
    
    // lazy_load_aux를 인자로 받아온 aux로 세팅
    struct load_aux *lazy_load_aux =  (struct load_aux *)aux;

    // 받아온 aux로 파일을 쓰기 위한 각 변수 세팅
    size_t page_read_bytes = lazy_load_aux->page_read_bytes;
    size_t page_zero_bytes = lazy_load_aux->page_zero_bytes;
    struct file *file = lazy_load_aux->file;
    off_t ofs = lazy_load_aux->ofs;

    // 써야할 파일의 오프셋으로 오프셋 옮기기
    file_seek (file, ofs);

    // 원하는 파일을 kpage에 로드
    // 파일을 읽어오지 못한 경우
    if (file_read (file, page->frame->kva, page_read_bytes) != (int) page_read_bytes){
        palloc_free_page(page->frame->kva);
        // false 리턴
        return false;
    }
    else{
        // 파일을 읽어온 경우
        // 파일 쓰기 - 4kb중 파일을 쓰고 남는 부분은 0으로 채움
        memset (page->frame->kva + page_read_bytes, 0, page_zero_bytes);

        // 메모리 반환
        // free(lazy_load_aux);

        // true 리턴
        return true;
    }
}
/* ------------------------- project3-2-1_Anonymous Page_Lazy Loading for Executable ------------------------ */

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
// 메인 루프 안에서 파일로부터 읽을 바이트의 수와 0으로 채워야 할 바이트의 수를 측정
// 대기 중인 오브젝트를 생성하는 vm_alloc_page_with_initializer함수를 호출
// vm_alloc_page_with_initializer에 제공할 aux 인자로써 보조 값들을 설정 → 구조체 생성
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
    ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT (pg_ofs (upage) == 0);
    ASSERT (ofs % PGSIZE == 0);

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
        /* ------------------------- _Anonymous Page_Lazy Loading for Executable ------------------------ */
        // aux 메모리 할당 
        // void *aux = NULL;
        struct load_aux *load_aux = (struct load_aux *)calloc(1, sizeof(struct load_aux));
        // aux 세팅       
        load_aux->page_read_bytes = page_read_bytes;
        load_aux->page_zero_bytes = page_zero_bytes;
        load_aux->file = file;
        load_aux->ofs = ofs;

        // 대기중인 오브젝트 생성 - 초기화되지 않은 주어진 타입의 페이지 생성
        if (!vm_alloc_page_with_initializer (VM_ANON, upage, writable, lazy_load_segment, load_aux))
            return false;

        /* Advance. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;

        // 다음 파일을 위해 파일을 읽은 바이트만큼 오프셋 이동
        ofs += page_read_bytes;
        /* ------------------------- _Anonymous Page_Lazy Loading for Executable ------------------------ */
    }

    return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
// USER_STACK에 스택 페이지를 생성
// 스택 할당 부분이  새로운 메모리 관리 시스템에 적합하도록 수정
// 첫 스택 페이지는 지연적으로 할당될 필요가 없음
// 페이지 폴트가 발생하는 것을 기다릴 필요 없이 스택 페이지를 load time 때 커맨드 라인의 인자들과 함께 할당하고 초기화 할 수 있음
// 스택 확인 → vm.h의 vm_type에 있는 보조 marker(ex : VM_MARKER_0)를 사용할 수 있음
static bool
setup_stack (struct intr_frame *if_) {
    bool success = false;
    void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

    /* TODO: Map the stack on stack_bottom and claim the page immediately.
     * TODO: If success, set the rsp accordingly.
     * TODO: You should mark the page is stack. */
    /* TODO: Your code goes here */
    // 스택을 stack_bottom에 매핑하고 페이지 할당
    // 성공시 rsp 설정

    // 스택에 페이지 생성
    if (vm_alloc_page_with_initializer(VM_STACK, stack_bottom, true, NULL, NULL))
    {   
        // va에 페이지를 할당하고, 해당 페이지에 프레임 할당하고 mmu 설정
        if (vm_claim_page(stack_bottom))
        {   
            // rsp 설정
            if_->rsp = USER_STACK;

			/* ----------------------------------- project3-2_Stack Growth ----------------------------------- */ 
            // 스택의 끝부분 저장
            thread_current()->stack_bottom = stack_bottom;
			/* ----------------------------------- project3-2_Stack Growth ----------------------------------- */ 

            // success를 true로 값 변경
            success = true;
        }
    }

    return success;
}
#endif /* VM */
