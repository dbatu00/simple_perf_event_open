#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#define _GNU_SOURCE 1
#include <string.h>

#include <unistd.h>
#include <fcntl.h>

#include <errno.h>

#include <signal.h>

#include <sys/ptrace.h>

#include <sys/mman.h>

#include <sys/ioctl.h>
#include <asm/unistd.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

#define NUM_THREADS	5

int test_var1;
int tid_array[NUM_THREADS];

long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
         int cpu, int group_fd, unsigned long flags)
{
   int ret;

   ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
   return ret;
}

void *PrintHello(void *threadid)
{
   long tid;
   int i;
   tid = (long)threadid;
   tid_array[tid] = syscall(SYS_gettid);
   for(int i=0;i<100000000;i++);
   if(tid == 2) {
	   struct perf_event_attr pe;
	   int fd1, bp_counter, read_result;
	   memset(&pe,0,sizeof(struct perf_event_attr));
	   pe.type=PERF_TYPE_BREAKPOINT;
           pe.size=sizeof(struct perf_event_attr);
	   pe.config=0;
	   pe.bp_type=HW_BREAKPOINT_W;
	   pe.bp_addr=(unsigned long)&test_var1;
	   pe.bp_len=sizeof(int);
	   pe.disabled=1;
	   pe.exclude_kernel=1;
	   pe.exclude_hv=1;

	   fd1=perf_event_open(&pe, tid_array[3],-1,-1,0);
	   if (fd1<0) {
		   fprintf(stderr,"Error opening leader %llx\n",pe.config);
	   }

	   ioctl(fd1, PERF_EVENT_IOC_RESET, 0);
           int ret=ioctl(fd1, PERF_EVENT_IOC_ENABLE,0);

	   /*for(int i=0;i<10000;i++) {
                //sum+=test_function(i,sum);
                test_var1 = i;
	   }*/
	   /*for(int i=0;i<10000;i++) {
                //sum+=test_function(i,sum);
                test_var1 = i;
           }*/
	   for(int i=0;i<100000000;i++);
	   ioctl(fd1, PERF_EVENT_IOC_DISABLE,0);
	   read_result=read(fd1,&bp_counter,sizeof(long long));
	   close(fd1);
	   printf("counter value: %d in thread %ld\n", bp_counter, tid);
   }

   if (tid == 3) {
	   for(int i=0;i<100000000;i++) {
                //sum+=test_function(i,sum);
                test_var1 = i;
           }
   }

   //printf("Hello World! It's me, thread #%ld!\n", tid);
   //for(i = 0; i < 100000000; i++);
   printf("Hello World! It's me, thread #%ld, i: %d, tid: %ld!\n", tid, i, syscall(SYS_gettid));
   pthread_exit(NULL);
}

int main(int argc, char *argv[])
{
   pthread_t threads[NUM_THREADS];
   int rc;
   long t;
   for(t=0;t<NUM_THREADS;t++){
     printf("In main: creating thread %ld\n", t);
     rc = pthread_create(&threads[t], NULL, PrintHello, (void *)t);
     if (rc){
       printf("ERROR; return code from pthread_create() is %d\n", rc);
       exit(-1);
       }
     }

   /* Last thing that main() should do */
   pthread_exit(NULL);
}
