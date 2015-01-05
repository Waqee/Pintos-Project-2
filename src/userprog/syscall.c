#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");

  int * p = f->esp;

  int system_call = * p;

	switch (system_call)
	{
		case SYS_WRITE:
		printf("fd : %d | Length : %d\n",*(p+5),*(p+7));
		printf("buffer: %s\n",*(p+6));
		break;

		default:
		printf("No match\n");
	}

  thread_exit ();
}
