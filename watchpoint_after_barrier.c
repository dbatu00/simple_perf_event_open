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

#define NUM_THREADS     5

pthread_barrier_t global_barrier;

int test_var1;
int test_var2;
int tid_array[NUM_THREADS];
int fds[NUM_THREADS];

long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
         int cpu, int group_fd, unsigned long flags)
{
   int ret;

   ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
   return ret;
}

void* thread_func(void* args) {
    long tid = (long) args;
    int i;
    int bp_counter, read_result, bp_total_count;
    tid_array[tid] = syscall(SYS_gettid);
    printf("thread %ld is waiting here\n", tid);
    pthread_barrier_wait(&global_barrier);
    if(tid == 2) {
	   struct perf_event_attr pe;
	   memset(&pe,0,sizeof(struct perf_event_attr));
	   pe.type=PERF_TYPE_BREAKPOINT;
           pe.size=sizeof(struct perf_event_attr);
	   pe.config=0;
	   pe.bp_type=HW_BREAKPOINT_W;
	   pe.bp_addr=(unsigned long)&test_var2;
	   pe.bp_len=sizeof(int);
	   pe.disabled=1;
	   pe.exclude_kernel=1;
	   pe.exclude_hv=1;

	   /*fd1=perf_event_open(&pe, tid_array[3],-1,-1,0);
	   if (fd1<0) {
		   fprintf(stderr,"Error opening leader %llx\n",pe.config);
	   }

	   ioctl(fd1, PERF_EVENT_IOC_RESET, 0);
           int ret=ioctl(fd1, PERF_EVENT_IOC_ENABLE,0);*/

	   for(int i = 0; i < NUM_THREADS; i++) {
		fds[i]=perf_event_open(&pe, tid_array[i],-1,-1,0);
           	if (fds[i]<0) {
                	fprintf(stderr,"Error opening leader %llx\n",pe.config);
           	}

           	ioctl(fds[i], PERF_EVENT_IOC_RESET, 0);
           	int ret=ioctl(fds[i], PERF_EVENT_IOC_ENABLE,0);
	   }
	   /*for(int i=0;i<10000;i++) {
                //sum+=test_function(i,sum);
                test_var1 = i;
	   }*/
	   /*for(int i=0;i<10000;i++) {
                //sum+=test_function(i,sum);
                test_var1 = i;
           }*/
   }
   printf("waiting for barrier 2 in thread %ld\n", tid);
   pthread_barrier_wait(&global_barrier);
   if (tid == 0 || tid == 2 || tid == 4) {
	   for(int i=0;i<1000000;i++) {
                //sum+=test_function(i,sum);
                test_var1 = i;
           }
   }
   if (tid == 1 || tid == 3) {
           for(int i=0;i<1000000;i++) {
                //sum+=test_function(i,sum);
                test_var2 = i;
           }
   }
    printf("waiting for barrier 3 in thread %ld\n", tid);
    pthread_barrier_wait(&global_barrier);
    if(tid == 2) {
	   for(int i = 0; i < NUM_THREADS; i++) {
	   	ioctl(fds[i], PERF_EVENT_IOC_DISABLE,0);
	   	read_result=read(fds[i],&bp_counter,sizeof(long long));
		bp_total_count += bp_counter;
	   	close(fds[i]);
	    }
	   printf("counter value: %d in thread %ld\n", bp_total_count, tid);
    }
    printf("passed barrier\n");

    return NULL;
}

int main() {
    pthread_t threads[NUM_THREADS];
    //struct barrier_and_id *barrier_tid_ptr = &barrier_tid;

    pthread_barrier_init(&global_barrier, NULL, NUM_THREADS);

    long i;
    for (i = 0; i < NUM_THREADS; i++) {
        pthread_create(&threads[i], NULL, thread_func, (void*)i);
    }

    for (i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}
