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
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

#define MAX_ARGS 3
#define USER_VADDR_BOTTOM ((void *)0x08048000)

// lock of filesys resource
struct lock filesys_lock;

static void syscall_handler (struct intr_frame *);

void ger_args(struct intr_frame*, int*, int);
void is_valid_ptr (const void *vaddr);
struct file* process_get_file (int fd);

void
syscall_init (void) 
{
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

void s_halt(void){
    //power_off();
    shutdown_power_off();
}

void s_exit(int status){
    /* RHS suggestion*/
    struct thread *cur = thread_current();
    /*
    if (cur->parent is alive){
        if (cur has no sibling){
            cur->parent->childrenNext = cur->parent->childrenPrev = cur->parent;
        }
        else{ // cur has siblings
            if (cur is NextMost sibling){ // cur->parent->childrenNext == cur
                cur->parent->childrenNext = cur->siblingPrev;
                cur->siblingPrev->siblingNext = cur->siblingPrev;
            }else if (cur is PrevMost sibling){ // cur->parent->childrenPrev == cur
                cur->parent->childrenPrev = cur->siblingNext;
                cur->siblingNext->siblingPrev = cur->siblingNext;
            }else{
                cur->siblingNext->siblingPrev = cur->siblingPrev;
                cur->siblingPrev->siblingNext = cur->siblingNext;
            }
        }
    }

    */
    char copy_name[16];
    char *file_name, *sv;
    strlcpy(copy_name, cur->name, strlen(cur->name)+1);
    file_name = strtok_r(copy_name, " ", &sv);
    printf("%s: exit(%d)\n",file_name, status);
    sema_up(&cur->wait_sema);
        
    thread_exit();
}


int s_write(int fd, const void *buffer, unsigned size){
    int actual_size = size;
    //printf("s_write is called\n");
    if (fd == STDOUT_FILENO){
        putbuf(buffer, size);
        return size;
    }
    lock_acquire(&filesys_lock);
    struct file *f = process_get_file(fd);
    if (!f){
        lock_release(&filesys_lock);
        return -1; // ERROR
    }
    int bytes = file_write(f, buffer, size);
    lock_release(&filesys_lock);
    /*while ((char *)buffer!=0){
        printf("%c",(char *)buffer);
        buffer+=1;
    }*/
    return bytes;
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
  // TODO <check esp is valid> 
  nsyscall = *(esp++);
  //printf ("system call!\n");
  //debugging(nsyscall);
  //thread_exit ();
  
    switch(nsyscall){
        // Process-related
        case SYS_EXIT:
            get_args(f,&args[0],2);
            s_exit(args[1]); // args[1] for exit_status
            break;
        case SYS_EXEC:
            break;
        case SYS_HALT:
            s_halt();
            break;
        case SYS_WAIT:
            break;
        // File-related
        case SYS_CREATE:
            break;
        case SYS_REMOVE:
            break;
        case SYS_OPEN:
            break;
        case SYS_FILESIZE:
            break;
        case SYS_READ:
            break;
        case SYS_WRITE:
            // read file_description, buffer, size
            get_args(f, &args[0], 3);
            f->eax = s_write(args[0], (const void *)args[1], (unsigned) args[2]);
            break;
        case SYS_SEEK:
            break;
        case SYS_TELL:
            break;
        case SYS_CLOSE:
            break;
        default:
            break;
    }
}

// Return file pointer for certain fd
struct file* process_get_file (int fd){
    struct thread *t = thread_current();
    int i;
    for (i=0;i<t->fd_cnt;i++){
        if (t->fd[i] == fd){
            return t->file_list[i];
        }
    }
    return NULL;
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

void is_valid_ptr(const void *vaddr){
    if (!is_user_vaddr(vaddr));
        //exit(ERROR);
    if (vaddr < USER_VADDR_BOTTOM); // 0x08048000
        //exit(ERROR);
}
