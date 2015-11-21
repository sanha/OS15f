#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "filesys/inode.h"

#define MAX_ARGS 3
#define USER_VADDR_BOTTOM ((void *)0x08048000)

// lock of filesys resource
struct lock filesys_lock;

static void syscall_handler (struct intr_frame *);

void ger_args(struct intr_frame*, int*, int);
void is_valid_ptr (const void *vaddr);
void is_valid_buffer (void *, unsigned);
int user_to_kernel(const void *vaddr);
void check_valid_string(const void* str);

static int s_add_file(struct file *f);
static int s_add_dir(struct dir *d);
static struct file* s_get_file_elem(int fd);
static void s_close_file(int fd);

void
syscall_init (void) 
{
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Process-Related System Calls */
void s_halt(void);
void s_exit(int status);
pid_t s_exec(const char *cmd_line);
int s_wait(pid_t pid);

/* File-Related System Calls */
bool s_create(const char *file, unsigned initial_size);
bool s_remove(const char *file);
int s_open(const char *file);
int s_filesize(int fd);
int s_read(int fd, void *buffer, unsigned size);
int s_write(int fd, const void *buffer, unsigned size);
void s_seek(int fd, unsigned position);
unsigned s_tell(int fd);
void s_close(int fd);
bool s_chdir(const char *dir);
bool s_mkdir(const char *dir);
bool s_readdir(int fd, char *name);
bool s_isdir(int fd);
int s_inumber(int fd);



void s_halt(void){
    //power_off();
    shutdown_power_off();
}

void s_exit(int status){
	/* RHS suggestion*/
    struct thread *cur = thread_current();

    /* TODO
       1. close every file -> file_close()
       2. delete myself
       3. every child connect to idle thread
       4. sema_up wait_sema                        // Clear
       */

    char copy_name[16];
    char *file_name, *sv;
    strlcpy(copy_name, cur->name, strlen(cur->name)+1);
    file_name = strtok_r(copy_name, " ", &sv);
    printf("%s: exit(%d)\n",file_name, status);
	//cur->zombie_flag=1;
	sema_up(&cur->zombie_sema);
	cur->exit_status = status;
	s_close_file(FD_ALL);
    // 4.
    sema_down(&cur->wait_sema);
	
    // 1.

    // 3.
    struct thread* child = cur->childrenNext;
    while (child!=cur){
        set_hierarchy_addition(child);
        if (child->siblingPrev == child)
            break;
        child = child->siblingPrev;
    }
    

    // 2.
    set_hierarchy_delete(); // delete myself
    //printf("			cur->file_name = %s\n",cur->file_name == NULL ? "NULL" : "NOT NULL");
	if (cur->file_name) file_close(cur->file_name);
    sema_up(&cur->exit_sema); 	
	//printf("	@ s_exit left space is: %d\n", left_space());	
	thread_exit();
}

int s_wait(pid_t pid){
	struct thread *cur = thread_current();
	struct thread *child = cur->childrenNext;
	while (child!=cur) {
		if (child->tid == pid) {
			return process_wait(pid);
		}
		else {
			if (child == child->siblingPrev) return -1;
			child = child->siblingPrev;
		}
	}
	return -1;
}

pid_t s_exec(const char *cmd_line){
	pid_t pid;

	pid = process_execute(cmd_line);
	//printf("			@ s_exec, pid = %d\n",pid);

	struct thread* child;
	struct thread* cur = thread_current();
	for (child = cur->childrenNext ; child!=cur ; child = child->siblingPrev){
		if (child->tid == pid){
			child->load_wait = 1;
			/*while (child->load_status != LOAD_SUCCESS && child->load_status!=LOAD_FAILED){
				barrier();
			}*/
			sema_down(&child->exec_sema);

			enum Load_status child_load_status = child->load_status;
			sema_up(&child->load_sema);
			
			//printf("	@ s_exec left space is: %d\n", left_space());	
			/*if (child_load_status == LOAD_SUCCESS){
				printf("			child->load_status = %d\n", 1);
			}else if (child_load_status == LOAD_FAILED){
				printf("			child->load_status = %d\n", 0);
			}*/

			if (child_load_status == LOAD_FAILED){
				return PID_ERROR;
			}
			break;
		}
		if (child == child->siblingPrev) break;
	}

	if(pid == TID_ERROR) return PID_ERROR;
	else return pid;
}

bool s_create(const char *file, unsigned initial_size)
{
    bool success = false;
    
   lock_acquire(&filesys_lock);
    success = filesys_create(file, initial_size, false);
   lock_release(&filesys_lock);
    
    return success;
}

bool s_remove(const char *file)
{
    bool success = false;

   lock_acquire(&filesys_lock);
   success = filesys_remove(file);
   lock_release(&filesys_lock);

    return success;
}

int s_open(const char *file)
{
    struct file *f;
    int fd = ERROR;

   lock_acquire(&filesys_lock);
    f = filesys_open(file);
    if(f)
	{
		if(getProperty(file_get_inode(f)) == FILE){
			//file_deny_write(f);
			fd = s_add_file(f);
		}
		else fd = s_add_dir((struct dir *)f);
	}
   lock_release(&filesys_lock);

    return fd;
}

int s_filesize(int fd)
{
    struct file_elem *fe;
	struct file *f;
    int size = ERROR;

   lock_acquire(&filesys_lock);
    fe = s_get_file_elem(fd);
	if(!fe) {
		lock_release(&filesys_lock);
		return size;
	}
	f = fe->file;
    if(f)   size = file_length(f);
   lock_release(&filesys_lock);

    return size;
}

int s_read(int fd, void *buffer, unsigned size)
{
    struct file *f;
	struct file_elem *fe;
    int bytes = ERROR;

    if(fd == STDIN_FILENO)
    {
        int i;
        uint8_t *buff = (uint8_t *)buffer;
        for(i = 0; i < size; i++)
            buff[i] = input_getc();
        bytes = size;
    }
    else
    {
       lock_acquire(&filesys_lock);
        fe = s_get_file_elem(fd);
		if (!fe) {
			lock_release(&filesys_lock);
			return bytes;
		}
		f = fe->file;
        if(f)   bytes = file_read(f, buffer, size);
       lock_release(&filesys_lock);
    }
    return bytes;
}

int s_write(int fd, const void *buffer, unsigned size){
    struct file *f;
	struct file_elem *fe;
    int bytes = ERROR;
    //printf("s_write is called\n");
    if (fd == STDOUT_FILENO){
        putbuf(buffer, size);
        bytes = size;
    }
    else
    {
       lock_acquire(&filesys_lock);
        fe = s_get_file_elem(fd);
		if (!fe) {
			lock_release(&filesys_lock);
			return bytes;
		}
		f = fe->file;
        if (f && fe->property == FILE)  
		{
			//file_allow_write(f);
			bytes = file_write(f, buffer, size);
			//file_deny_write(f);
		}
       lock_release(&filesys_lock);
    }
    return bytes;
}

void s_seek(int fd, unsigned position)
{
    struct file *f;
	struct file_elem *fe;

   lock_acquire(&filesys_lock);
    fe = s_get_file_elem(fd);
	if (!fe) {
		lock_release(&filesys_lock);
		return ;
	}
	f = fe->file;
    if(f)   file_seek(f, position);
   lock_release(&filesys_lock);
}

unsigned s_tell(int fd)
{
    struct file *f;
	struct file_elem *fe;
    unsigned position = ERROR;

   lock_acquire(&filesys_lock);
    fe = s_get_file_elem(fd);
	if (!fe) {
		lock_release(&filesys_lock);
		return position;
	}
	f = fe->file;
    if(f)   position = file_tell(f);
   lock_release(&filesys_lock);
    
    return position;
}

void s_close(int fd)
{
    lock_acquire(&filesys_lock);
    s_close_file(fd);
    lock_release(&filesys_lock);
}

bool s_chdir(const char *dir)
{
	return filesys_chdir(dir);
}

bool s_mkdir(const char *dir)
{
	return filesys_create(dir, 0, true);
}

bool s_readdir(int fd, char *name)
{
	struct list_elem *e;
	struct file_elem *fe;

	fe = s_get_file_elem(fd);
	if(fe == NULL) return false;
	if(fe->property == FILE) return false;

	if(!dir_readdir(fe->fd,fe->dir)) {
		//printf("		@ s_readdir dir_readdir_failed\n");
		return false;
	}


	return true;
}

bool s_isdir(int fd)
{
	struct file_elem *fe = s_get_file_elem(fd);
	if(!fe) return ERROR;
	if(fe->property == DIR) return true;
	else return false;
}

int s_inumber(int fd)
{
	struct file_elem *fe = s_get_file_elem(fd);
	if(!fe) {
		return ERROR;
	}

	block_sector_t inumber;
	if(fe->property == DIR) inumber = inode_getSector(dir_get_inode(fe->dir));
	else inumber = inode_getSector(file_get_inode(fe->file));

	printf("		@ s_inumber fd = %d, inumber = %d\n", fd, inumber);

	return inumber;
}

static void debugging(int syscall_type){
    switch(syscall_type){
        // Process-related
        case SYS_EXIT:
            printf("SYS_EXIT!\n"); break;
        case SYS_EXEC:
            printf("SYS_EXEC!\n"); break;
        case SYS_HALT:
            printf("SYS_HALT!\n"); break;
        case SYS_WAIT:
            printf("SYS_WAIT!\n"); break;
        // File-related
        case SYS_CREATE:

            printf("SYS_CREATE!\n"); break;
        case SYS_REMOVE:
            printf("SYS_REMOVE!\n"); break;
        case SYS_OPEN:
            printf("SYS_OPEN!\n"); break;
        case SYS_FILESIZE:
            printf("SYS_FILESIZE!\n"); break;
        case SYS_READ:
            printf("SYS_READ!\n"); break;
        case SYS_WRITE:
            printf("SYS_WRITE!\n"); break;
        case SYS_SEEK:
            printf("SYS_SEEK!\n"); break;
        case SYS_TELL:
            printf("SYS_TELL!\n"); break;
        case SYS_CLOSE:
            printf("SYS_CLOSE!\n"); break;
        default:
            printf("WRONG SYSCALL!\n");
    }
}
    
static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int nsyscall, ret;
  int args[MAX_ARGS];
  int *esp = (int *)f->esp;
  
  user_to_kernel((const void *)esp);
  nsyscall = *(esp++);
  //printf ("system call!\n");
  //debugging(nsyscall);
  //thread_exit ();
  
    switch(nsyscall){
        // Process-related
        case SYS_EXIT:
            get_args(f,&args[0],1);
            s_exit(args[0]); // args[0] for exit_status
            break;
        case SYS_EXEC:
            get_args(f, &args[0], 1);
            args[0] = user_to_kernel((const void *) args[0]);
            f->eax = s_exec((const char *)args[0]);
            break;
        case SYS_HALT:
            s_halt();
            break;
        case SYS_WAIT:
            get_args(f,&args[0],1);
            f->eax = s_wait(args[0]);
            break;
        // File-related
        case SYS_CREATE:
            get_args(f, &args[0], 2);
            args[0] = user_to_kernel((const void *)args[0]);
            f->eax = s_create((const char *)args[0],(unsigned)args[1]);
            break;
        case SYS_REMOVE:
            get_args(f, &args[0], 1);
            args[0] = user_to_kernel((const void *)args[0]);
            f->eax = s_remove((const char *)args[0]);
            break;
        case SYS_OPEN:
            get_args(f, &args[0], 1);
            args[0] = user_to_kernel((const void *)args[0]);
            f->eax = s_open((const char *)args[0]);
            break;
        case SYS_FILESIZE:
            get_args(f, &args[0], 1);
            f->eax = s_filesize((int)args[0]);
            break;
        case SYS_READ:
            get_args(f, &args[0], 3);
            is_valid_buffer((void *)args[1], (unsigned) args[2]);
            args[1] = user_to_kernel((const void *)args[1]);
            f->eax = s_read((int)args[0],(const void *)args[1], (unsigned)args[2]);
            break;
        case SYS_WRITE:
            // read file_description, buffer, size
            get_args(f, &args[0], 3);
            is_valid_buffer((void *) args[1], (unsigned) args[2]);
            args[1] = user_to_kernel((const void *)args[1]);
            f->eax = s_write(args[0], (const void *)args[1], (unsigned) args[2]);
            break;
        case SYS_SEEK:
            get_args(f, &args[0], 2);
            s_seek((int)args[0], (unsigned)args[1]);
            break;
        case SYS_TELL:
            get_args(f, &args[0], 1);
            f->eax = s_tell((int)args[0]);
            break;
        case SYS_CLOSE:
            get_args(f, &args[0], 1);
            s_close((int)args[0]);
            break;
		case SYS_CHDIR:
			get_args(f, &args[0], 1);
			check_valid_string((const void *) args[0]);
			args[0] = user_to_kernel((const void *) args[0]);
			f->eax = s_chdir((const char *) args[0]);
			break;
		case SYS_MKDIR:
			get_args(f, &args[0], 1);
			check_valid_string((const void *) args[0]);
			args[0] = user_to_kernel((const void *) args[0]);
			f->eax = s_mkdir((const char *) args[0]);
			break;
		case SYS_READDIR:
			get_args(f, &args[0], 2);
			check_valid_string((const void *) args[1]);
			args[1] = user_to_kernel((const void *) args[1]);
			f->eax = s_readdir((int)args[0],(const char *) args[1]);
			break;
		case SYS_ISDIR:
			get_args(f, &args[0], 1);
			f->eax = s_isdir((int)args[0]);
			break;
		case SYS_INUMBER:
			get_args(f, &args[0], 1);
			f->eax = s_inumber((int)args[0]);
			break;
        default:
            break;
    }
}

int s_add_file(struct file *f)
{
   struct thread *t = thread_current();
   struct file_elem *fe = malloc(sizeof(struct file_elem));
   fe->property = FILE;
   fe->file = f;
   fe->fd = t->fd++;
   list_push_back(&t->u_open_files, &fe->elem);
   return fe->fd;
}

int s_add_dir(struct dir *d)
{
   struct thread *t = thread_current();
   struct file_elem *fe = malloc(sizeof(struct file_elem));
   fe->property = DIR;
   fe->dir = d;
   fe->fd = t->fd++;
   list_push_back(&t->u_open_files, &fe->elem);
   return fe->fd;
}

// Return file pointer for certain fd
struct file* s_get_file_elem (int fd){
    struct thread *t = thread_current();
    struct list_elem *e;
    struct file_elem *fe;

    for(e = list_begin(&t->u_open_files); e != list_end(&t->u_open_files); e = list_next(e))
    {
        fe = list_entry(e, struct file_elem, elem);
        if(fd == fe->fd)
            return fe;
    }
    return NULL;
}

void s_close_file(int fd)
{
    struct thread *t = thread_current();
    struct list_elem *e;
    struct file_elem *fe;

    for(e = list_begin(&t->u_open_files); e != list_end(&t->u_open_files);)
    {
        fe = list_entry(e, struct file_elem, elem);
		e = list_next(e);
        if(fd == fe->fd || fd == FD_ALL)
        {
            if (fe->property == FILE) file_close(fe->file);
			else dir_close(fe->dir);
            list_remove(&fe->elem);
            free(fe);
            if(fd != FD_ALL)
                return;
        }
    }
}
    
    
// Get args (args count) from stack, and save it in *args
void get_args(struct intr_frame *f, int *args, int argc){
    int i, *ptr;
    for (i=1;i<=argc;i++){
        ptr = ((int*)f->esp + i);
        is_valid_ptr((const void *)ptr);
        args[i-1] = *ptr;
    }
}

void is_valid_buffer(void *buf, unsigned size){
	int i;
	char *cbuf = (char *)buf;
	for (i=0;i<size;i++){
		is_valid_ptr(cbuf++);
	}
}

void is_valid_ptr(const void *vaddr){
    if (!is_user_vaddr(vaddr))
        s_exit(ERROR);
    if (vaddr < USER_VADDR_BOTTOM) // 0x08048000
        s_exit(ERROR);

}

int user_to_kernel(const void *vaddr)
{
	is_valid_ptr(vaddr);
	void *p = pagedir_get_page(thread_current()->pagedir, vaddr);
	if(!p) {s_exit(ERROR);}
	return (int) p;
}

void check_valid_string(const void* str)
{
	while(*(char *)user_to_kernel(str) != 0){
		str = (char *)str + 1;
	}
}
