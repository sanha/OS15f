#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

#define USER_VADDR_BOTTOM ((void *)0x08048000)

static void syscall_handler (struct intr_frame *);

void ger_args(struct intr_frame*, int*, int);
void is_valid_ptr (const void *vaddr);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
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
  int *esp = (int *)f->esp;
  // TODO <check esp is valid> 
  nsyscall = *(esp++);
  printf ("system call!\n");
  debugging(nsyscall);
  //thread_exit ();
  
    switch(nsyscall){
        // Process-related
        case SYS_EXIT:
            break;
        case SYS_EXEC:
            break;
        case SYS_HALT:
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

void get_args(struct intr_frame *f, int *args, int argc){
    int i;
    for (i=1;i<=argc;i++){
        args[i] = *((int*)f->esp + i);
        is_valid_ptr((const void *)args[i]);
    }
}

void is_valid_ptr(const void *vaddr){
    if (!is_user_vaddr(vaddr));
        //exit(ERROR);
    if (vaddr < USER_VADDR_BOTTOM); // 0x08048000
        //exit(ERROR);
}
