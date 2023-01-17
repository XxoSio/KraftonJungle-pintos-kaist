#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* ----------------------------------- project2-2_User Memory Access ----------------------------------- */
void check_address(void *addr);

void halt(void);
void exit (int status);
int fork (const char *thread_name, struct intr_frame *f UNUSED);
int exec (const char *file);
int wait (tid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
/* ----------------------------------- project2-2_User Memory Access ----------------------------------- */

void *mmap(void *addr, size_t length, int writable, int fd, off_t offset);
void munmap(void *addr);

/* ----------------------------------- project2-3-1_System calls-File Descriptor ----------------------------------- */
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
// project2-3-2_System calls-Process
#include "threads/palloc.h"

int process_add_file (struct file *f);
struct file *process_get_file(int fd);
void process_close_file(int fd);
/* ----------------------------------- project2-3-1_System calls-File Descriptor ----------------------------------- */

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	/* ----------------------------------- project2-3-1_System calls-File Descriptor ----------------------------------- */
	// 잠금 초기화
	lock_init(&file_lock);
	/* ----------------------------------- project2-3-1_System calls-File Descriptor ----------------------------------- */
}

/* ----------------------------------- project2-2_User Memory Access ----------------------------------- */
/* ------------------------------ project3-2-2_Supplemental Page Table - Revisit ------------------------------ */
// 포인터가 가리키는 주소가 사용자 영역인지 확인
// 사용자 영역을 벗어난 경우 프로세스 종료
void check_address(void *addr){
	if(!is_user_vaddr(addr) || addr == NULL){
		exit(-1);
	}

	#ifdef VM
	// pml4_get_page()를 호출하여 주소에 pml4로 매핑되어 있는 페이지가 있는지 확인
	if(pml4_get_page (&thread_current()->pml4, addr) == NULL)
		// 매핑되어 있는 페이지가 없다면 대기중인 보조 페이지 테이블이 있는지 확인
		if (spt_find_page(&thread_current()->spt, addr) == NULL)
			// 보조 페이지 테이블이 없다면 -1로 종료
			exit(-1);
	#endif
}
/* ------------------------------ project3-2-2_Supplemental Page Table - Revisit ------------------------------ */
/* ----------------------------------- project2-2_User Memory Access ----------------------------------- */

/* ----------------------------------- project3_Clean up code----------------------------------- */
// read, write의 경우 접근이 가능한 페이지인지 확인
void check_buffer(void* buffer, unsigned size, void* rsp, bool write){
	// 버퍼 주소 확인
	check_address(buffer);

	// 확인할 주소의 보조 페이지 찾기
	struct page* page = spt_find_page(&thread_current()->spt, buffer);

	// 페이지를 못찾은 경우
	if(page == NULL)
		// -1로 종료
		exit(-1);
	// 인자로 받은 write의 권한이 false이고, 접근하려는 페이지의 write의 권한이 false인 경우
	if(write == false && page->writable == false)
		// -1로 종료
		exit(-1);
}
/* ----------------------------------- project3_Clean up code ----------------------------------- */

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.

	/* ----------------------------------- project2-2_User Memory Access ----------------------------------- */
	// 기존 코드
	// printf ("system call!\n");
	// thread_exit ();

	// 유저 스택에 저장되어 있는 시스템 콜 넘버 받아오기
	int syscall_num = f->R.rax;
	// 에러 잡기 시스템콜 확인용 코드
	// printf("system call num : %d\n", syscall_num);

	switch (syscall_num)
	{
	// 시스템 콜 넘버 : 0
	// power_off()를 호출해 핀토스를 종료
	case SYS_HALT:
		halt();
		break;
	// 시스템 콜 넘버 : 1
	// 현재 사용자 프로그램을 종료하고, 커널에 상태를 반환
	// 0이 아니면 오류값
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	// 시스템 콜 넘버 : 2
	// THREAD_NAME이라는 이름을 가진 현재 프로세스의 복제복인 새 프로세스 생성
	case SYS_FORK:
		f->R.rax = fork(f->R.rdi, f);
		break;
	// 시스템 콜 넘버 : 3
	// 주어진 인수를 전달하여 cmd_line에 이름이 지정된 실행 파일로 현재 프로세스를 변경
	// 잘못되는 경우, 프로세스가 -1로 종료
	case SYS_EXEC:
		f->R.rax = exec(f->R.rdi);
		break;
	// 시스템 콜 넘버 : 4
	// 자식 프로세스 pid를 기다리고 자식의 종료 상태를 검색
	case SYS_WAIT:
		f->R.rax = wait(f->R.rdi);
		break;
	// 시스템 콜 넘버 : 5
	// initial_size를 갖는 file이라는 이름의 새 파일을 만듦
	case SYS_CREATE:
		f->R.rax = create(f->R.rdi, f->R.rsi);
		break;
	// 시스템 콜 넘버 : 6
	// file이라는 이름을 갖는 파일을 삭제
	case SYS_REMOVE:
		f->R.rax = remove(f->R.rdi);
		break;
	// 시스템 콜 넘버 : 7
	// file이라는 이름의 파일을 열어줌
	case SYS_OPEN:
		f->R.rax = open(f->R.rdi);
		break;
	// 시스템 콜 넘버 : 8
	// fd로 열린 파일의 바이트를 반환
	case SYS_FILESIZE:
		f->R.rax = filesize(f->R.rdi);
		break;
	/* ----------------------------------- project3_Clean up code ----------------------------------- */
	// 시스템 콜 넘버 : 9
	// fd로 열린 파일에서 버퍼로 크기 바이트를 읽음
	case SYS_READ:
		check_buffer(f->R.rsi, f->R.rdx, f->rsp, 0);
		f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	// 시스템 콜 넘버 : 10
	// 버퍼에서 열린파일 fd에 크기 바이트를 씀
	case SYS_WRITE:
		check_buffer(f->R.rsi, f->R.rdx, f->rsp, 1);
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	/* ----------------------------------- project3_Clean up code ----------------------------------- */
	// 시스템 콜 넘버 : 11
	// 열린 파일fd에서 읽거나 쓸 다음 바이트를 위치로 변경
	case SYS_SEEK:
		seek(f->R.rdi, f->R.rsi);
		break;
	// 시스템 콜 넘버 : 12
	// 열린 파일 fd에서 읽거나 쓸 다음 바이트의 위치를 파일 시작부터 바이트 단위로 반환
	case SYS_TELL:
		f->R.rax = tell(f->R.rdi);
		break;
	// 시스템 콜 넘버 : 13
	// 파일 디스크립터 fd를 닫음
	case SYS_CLOSE:
		close(f->R.rdi);
		break;
	/* ----------------------------------- project3-4_Memory Mapped Files ----------------------------------- */
	// 시스템 콜 넘버 : 14
	// 파일을 가상 주소에 매핑
	case SYS_MMAP:
		f->R.rax = mmap(f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
		break;
	// 시스템 콜 넘버 : 15
	// 파일을 가상 주소에서 매핑 해제
	case SYS_MUNMAP:
		munmap(f->R.rdi);
		break;
	/* ----------------------------------- project3-4_Memory Mapped Files ----------------------------------- */
	// 예외 처리
	default:
		exit(-1);
		break;
	}
	/* ----------------------------------- project2-2_User Memory Access ----------------------------------- */
}

/* ----------------------------------- project2-2_User Memory Access ----------------------------------- */

/* ----------------------------------- project2-3_System calls ----------------------------------- */
// 시스템 콜 넘버 : 0
// pintos를 종료시키는 시스템 콜
// power_off() 함수 호출
void
halt (void){
	power_off();
}

// 시스템 콜 넘버 : 1
// 현재 사용자 프로그램을 종료하고, 커널에 상태를 반환
// status : 프로세스의 종료 상태
void
exit (int status){
	struct thread *th = thread_current();

	/* -------------- project2-3-2_System calls-Process ------------- */
	// 스레드의 종료 상태를 알 수 있도록 종료 상태를 바꿔줌
	th->exit_status = status;
	/* -------------- project2-3-2_System calls-Process ------------- */

	// 종료되는 스레드 이름과 상태를 출력
	printf("%s: exit(%d)\n", th->name, status);
	// 스레드 종료
	thread_exit();
}
/* ----------------------------------- project2-3_System calls ----------------------------------- */

/* -------------- project2-3-2_System calls-Process ------------- */
// 시스템 콜 넘버 : 2
// THREAD_NAME이라는 이름을 가진 현재 프로세스의 복제복인 새 프로세스 생성
// thread_name : 프로세스 이름
// *f : 프로세스가 가지고 있는 인터럽트 프레임
int
fork (const char *thread_name, struct intr_frame *f UNUSED){
	// fork하는 스레드의 위치가 사용자 메모리 영역인지 확인
	check_address(thread_name);

	// process_fork() 호출
	// thread_name으로 현재 스레드 복제
	// 새로운 스레드의 tid를 반환
	return process_fork(thread_name, f);
}

// 시스템 콜 넘버 : 3
// 주어진 인수를 전달하여 cmd_line에 이름이 지정된 실행 파일로 현재 프로세스를 변경
// 즉, 주어진 파일을 실행
// cmd_line : 새로운 프로세스에 실행할 프로그램 명령어
int
exec (const char *cmd_line) {
	// exec하는 스레드의 위치가 사용자 메모리 영역인지 확인
	check_address(cmd_line);

	// cmd_line의 길이 가져오기
	// 마지막 '\n'까지 가져오기 위해 +1
	int size = strlen(cmd_line) + 1;
	// 페이지 할당
	char *fn_copy = palloc_get_page(PAL_ZERO);
	
	// 페이지 할당이 제대로 되지 않으면 -1로 종료
	if (fn_copy == NULL) {
		exit(-1);
	}
	// 할당이 제대로 된 경우
	else{
		// 해당 명령어의 사이즈 만큼 페이지에 복사
		strlcpy(fn_copy, cmd_line, size);

		// process_exec()를 실행하여 실행 context를 변경
		// 제대로 변경되지 않으면 -1 리턴
		if (process_exec(fn_copy) == -1) {
			return -1;
		}

		// executed 에러처리
		NOT_REACHED();

		// 모든 동작이 완료되면 정상 종료 값인 0 리턴
		return 0;
	}
}

// 시스템 콜 넘버 : 4
// 자식 프로세스 pid를 기다리고 자식의 종료 상태를 검색
int
wait (tid_t pid) {
	return process_wait(pid);
}
/* -------------- project2-3-2_System calls-Process ------------- */

/* ----------------------------------- project2-3-1_System calls-File Descriptor ----------------------------------- */
// 시스템 콜 넘버 : 5
// initial_size를 갖는 file이라는 이름의 새 파일을 만듦
// filesys_create() 함수 호출
// file : 생성할 파일의 이름 및 경로 정보
// initial_size : 생성할 파일의 크기
bool
create (const char *file, unsigned initial_size){
	// create하는 파일의 위치가 사용자 메모리 영역인지 확인
	check_address(file);

	// lock 설정
	lock_acquire(&file_lock);
	// filesys_create()로 initial_size 사이즈와
	// name이라는 이름을 가진 파일 생성
	bool success = filesys_create(file, initial_size);
	// lock 해제
	lock_release (&file_lock);

	// 파일 생성 성공 여부 반환
	return success;
}

// 시스템 콜 넘버 : 6
// file이라는 이름을 갖는 파일을 삭제
// filesys_remove() 함수 호출
// file : 제거할 파일의 이름 및 경로 정보
bool
remove (const char *file){
	// remove하는 파일의 위치가 사용자 메모리 영역인지 확인
	check_address(file);

	// lock 설정
	lock_acquire(&file_lock);
	// filesys_remove()로 name이라는 이름을 가진 파일 삭제
	bool success = filesys_remove(file);
	// lock 해제
	lock_release (&file_lock);

	// 파일 삭제 성공 여부 반환
	return success;
}

// 시스템 콜 넘버 : 7
// file이라는 이름의 파일을 열어줌
// filesys_open() 함수 호출
// file : 파일의 이름 및 경로 정보
int
open (const char *file) {
	// open하는 파일의 위치가 사용자 메모리 영역인지 확인
	check_address(file);

	// 받은 파일이 NULL이라면 -1 리턴
	if(file == NULL)
		return -1;

	// lock 설정
	lock_acquire(&file_lock);
	//process_add_file()로 파일 디스크립터 테이블에 저장후 인덱스 반환
	struct file *f = filesys_open(file);
	// lock 해제
	// lock_release(&file_lock);

	// 반환받은 파일의 위치가 비었으면 NULL 반환
	if(f == NULL){
		lock_release(&file_lock);
		return -1;
	}
	else{
		// process_add_file()로 파일 디스크립터 테이블에 저장후 인덱스 반환
		int fd = process_add_file(f);

		// 반환 받은 인덱스가 -1이라면 파일을 닫음
		if(fd == -1){
			// 열었던 파일 닫기
			file_close(f);
		}

		lock_release(&file_lock);
		// 정상적인 값이라면, 해당 인덱스 반환
		return fd;
	}
}

// 시스템 콜 넘버 : 8
// fd로 열린 파일의 바이트를 반환
// file_length() 함수 호출
// fd : 파일 디스크립터 번호
int
filesize (int fd) {
	// fd에 맞는 파일 위치 정보값 찾기
	struct file *f = process_get_file(fd);

	// 위치 정보값이 -1이면 -1 리턴
	if (f == -1)
	{
		return -1;
	}
	// 정상적인 위치 정보값이 들어온 경우
	else if(f){
		// 해당 파일 사이즈를 받아오기
		int result = file_length(f);

		// 받아온 파일 사이즈 리턴
		return result;
	}
}

// 시스템 콜 넘버 : 9
// fd로 열린 파일에서 버퍼로 크기 바이트를 읽음
// file_read() 함수 호출
// fd : 파일 디스크립터 번호
// buffer : 읽은 데이터를 저장할 버퍼의 주소값
// size : 읽을 데이터 크기
int
read (int fd, void *buffer, unsigned size) {
	// read하는 파일의 위치가 사용자 메모리 영역인지 확인
	// check_address(buffer);

	// buffer의 경우 주소값에 배열로 들어옴
	// 해당 배열값에 접근할 수 있도록 *buf 선언
	unsigned char *buf = buffer;
	// 읽은 사이즈를 저장하는 변수 선언
	int read_size;

	// fd에 맞는 파일 위치 정보값 찾기
	struct file *f = process_get_file(fd);

	// 위치 정보값이 -1이거나 STDOUT(2)이면 -1 리턴
	if(f == NULL || f == STDOUT){
		return -1;
	}
	// 위치 정보값으로 SRDIN(1)이 들어온 경우
	else if(f == STDIN){
		// 인자로 받아온 사이즈만큼 for문을 돌면서
		// input_getc()를 사용하여 한글자씩 받아와 버퍼에 저장
		for(read_size = 0; read_size == size; read_size++){
			char input_char = input_getc();
			*buf++ = input_char;

			// 저장한 값이 NULL이면 더이상 저장할 글자가 없으므로 break
			if(input_char == NULL)
				break;
		}
	}
	// 위치 정보값이 2 이상인 경우
	else{
		// lock 설정
		lock_acquire(&file_lock);
		// file을 읽은 사이즈 저장
		read_size = file_read(f, buffer, size);
		// lcok 해제
		lock_release(&file_lock);
	}

	// 최종적으로 읽어온 사이즈 리턴
	return read_size;
}

// 시스템 콜 넘버 : 10
// fd에 맞는 파일을 열어 버퍼에서 size 바이트 크기만큼 씀
// file_write() 함수 호출
// fd : 파일 디스크립터 번호
// buffer : 기록할 데이터를 저장한 버퍼의 주소 값
// size : 기록할 데이터의 크기
int
write (int fd, const void *buffer, unsigned size) {
	// write하는 파일의 위치가 사용자 메모리 영역인지 확인
	// check_address(buffer);

	// 쓰려고하는 사이즈를 저장하는 변수 선언
	int write_size;

	// fd에 맞는 파일 위치 정보값 찾기
	// struct file *f = thread_current()->file_descriptor_talbe[fd];
	struct file *f = process_get_file(fd);

	// 위치 정보값이 -1이거나 STDIN(1)이면 -1 리턴
	if(f == NULL || f == STDIN){
		return -1;
	}
	// 위치 정보값으로 STDOUT(2)이 들어온 경우
	else if(f == STDOUT){
		// putbuf()를 사용하여 버퍼에 사이즈만큼 쓰기
		putbuf(buffer, size);
		// 버퍼에 쓴 사이즈 저장
		write_size = size;
	}
	// 위치 정보값이 2 이상인 경우
	else{
		// lock 설정
		lock_acquire(&file_lock);
		// file에 쓴 사이즈 저장
		write_size = file_write(f, buffer, size);
		// lcok 해제
		lock_release(&file_lock);
	}

	// 최종적으로 쓴 사이즈 리턴
	return write_size;
}

// 시스템 콜 넘버 : 11
// fd에 맞는 파일을 열어 읽거나 쓸 다음 바이트를 위치로 변경
// file_seek() 함수 호출
// fd : 파일 디스크립터 번호
// Position : 현재 위치(offset)를 기준으로 이동할 거리
void
seek (int fd, unsigned position) {
	// fd에 맞는 파일 위치 정보값 찾기
	struct file *f = process_get_file(fd);

	// 파일 위치 정보값이 2이상인 경우
	if(f > 2)
		// file_seek()를 사용하여
		// 파일이 저장되어있는 위치 정보값을
		// 인자로 받아온 위치로 변경
		file_seek(f, position);
	// 파일 위치 정보값이 2이하인 경우
	else
		// -1 리턴
		return ;
}

// 시스템 콜 넘버 : 12
// fd에 맞는 파일을 열어 읽거나 쓸 다음 바이트의 위치를 파일 시작부터 바이트 단위로 반환
// file_tell() 함수 호출
// fd : 파일 디스크립터 번호
unsigned
tell (int fd) {
	// fd에 맞는 파일 위치 정보값 찾기
	struct file *f = process_get_file(fd);

	// 파일 위치 정보값이 2이상인 경우
	if(f > 2)
		// file_tell()을 사용하여
		// 현재 위치 정보 반환
		return file_tell(f);
	// 파일 위치 정보값이 2이하인 경우
	else
		// -1 리턴
		return ;
}

// 시스템 콜 넘버 : 13
// fd에 맞는 파일을 닫음
// fd : 파일 디스크립터 번호
void
close (int fd) {
	// lock 설정
	lock_acquire(&file_lock);
	// 인덱스 값에 맞는 파일 닫기
	process_close_file(fd);
	// lock 해제
	lock_release(&file_lock);
}
/* ----------------------------------- project2-3-1_System calls-File Descriptor ----------------------------------- */

/* ----------------------------------- project2-2_User Memory Access ----------------------------------- */

/* ----------------------------------- project2-3-1_System calls-File Descriptor ----------------------------------- */
// 파일 객체(struct file)를 파일 디스크립터 테이블에 추가
// 성공시 파일 객체의 파일 디스크립터 인덱스 반환, 실패시 -1 반환
int
process_add_file (struct file *f){
	struct thread *th = thread_current();
	struct file **curr_fdt = th->file_descriptor_talbe;

	// 최대 값보다 작거나 해당 인덱스가 비어있다면
	// 인덱스를 하나 늘리면서 비어있는 인덱스 찾기
	while ((th->file_descriptor_index < FDT_LIMIT) && (curr_fdt[th->file_descriptor_index]))
    {
        th->file_descriptor_index++;
    }

    // 인덱스가 최대와 같아지거나 커지면 -1 리턴
    if (th->file_descriptor_index >= FDT_LIMIT)
        return -1;

	// 찾은 인덱스에 파일 저장
    curr_fdt[th->file_descriptor_index] = f;

	// 새로운 파일 추가 후 해당 인덱스 리턴
    return th->file_descriptor_index;
}

// 파일 디스크립터 테이블에 있는 파일 검색
// 성공시 검색한 파일의 위치 주소(offset) 반환, 실패시 -1 반환
struct
file *process_get_file(int fd){
	struct thread *th = thread_current();
	// struct file **current_fdt = th->file_descriptor_talbe;

	// 찾고자 하는 파일 인덱스의 값이 잘못된 경우 -1 반환
	if(0 > fd || fd >= FDT_LIMIT)
		return NULL;
	// 올바른 인덱스의 값이 들어온 경우
	else{
		// 해당 인덱스에 있는 파일의 위치 주소(offset) 반환
		struct file *f = th->file_descriptor_talbe[fd];
		return f;
	}
}

// 파일 디스크립터 테이블에서 인자로 받은 인덱스의 파일 삭제
// 해당 인덱스 파일의 내용 삭제(초기화)
void
process_close_file(int fd){
	// 지우고자 하는 파일 인덱스의 값이 잘못된 경우 -1 반환
	if(0 > fd || fd >= FDT_LIMIT)
		return -1;
	else{
		// 해당 인덱스의 파일을 찾으면 내용을 NULL 변경하여 삭제(초기화)
		thread_current()->file_descriptor_talbe[fd] = NULL;
	}
}
/* ----------------------------------- project2-3-1_System calls-File Descriptor ----------------------------------- */

/* ----------------------------------- project3-4_Memory Mapped Files ----------------------------------- */
void *mmap(void *addr, size_t length, int writable, int fd, off_t offset){
	/* Return NULL의 경우 
	 * CASE 1. `addr` 가 0인 경우
	 * CASE 2. `addr` 가 커널 가상 주소인 경우
	 * CASE 3. `addr` 가 page-aligned 되지 않은 경우
	 * CASE 4. 기존에 매핑된 페이지 집합(stack, 페이지)과 겹치는 경우
	 * CASE 5. 읽으려는 파일의 offset 위치가 PGSIZE 보다 큰 경우
	 * CASE 6. 읽으려는 파일의 길이가 0보다 작거나 같은 경우
	 * CASE 7. STDIN, STDOUT 인 경우
	 * CASE 8. 파일 객체가 존재하지 않는 경우
	 * CASE 9. fd로 열린 파일의 길이가 0인 경우*/

	/* mmap-kernel TC
	 * kernel = (void *) 0x8004000000 - 0x1000;
  	 * CHECK (mmap (kernel, -0x8004000000 + 0x1000, 0, handle, 0) == MAP_FAILED,
     * "try to mmap over kernel 2"); */

	// CASE 1 - 6
    if (addr == NULL || \
		is_kernel_vaddr(addr) || is_kernel_vaddr(pg_round_up(addr)) || pg_round_down(addr) != addr || \
		spt_find_page(&thread_current()->spt, addr)	|| offset > PGSIZE || (long)length <= 0)
        return NULL;	

    struct file *file = process_get_file(fd);

	// CASE 7 - 9
    if (fd <= STDOUT_FILENO || file == NULL || file_length(file) == 0)
        return NULL;
	
	// 파일을 가상 주소 addr에 매핑
	// do_mmap의 4번째 인자가 파일 객체이므로 fd로 부터 파일 객체를 얻은 값을 넣어줌
    return do_mmap(addr, length, writable, file, offset);
}

void munmap(void *addr){
	// addr에 대한 매핑을 해제
	do_munmap(addr);
}
/* ----------------------------------- project3-4_Memory Mapped Files ----------------------------------- */