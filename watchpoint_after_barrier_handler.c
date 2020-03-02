#define _GNU_SOURCE 1
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
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
int overflow_count;

long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
         int cpu, int group_fd, unsigned long flags)
{
   int ret;

   ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
   return ret;
}

static void our_handler(int signum,siginfo_t *oh, void *blah) {

        int ret;

        ret=ioctl(oh->si_fd, PERF_EVENT_IOC_DISABLE, 0);

        printf("there is a signal from fd: %d handled by thread %ld\n", oh->si_fd, syscall(SYS_gettid));
	overflow_count++;

        ret=ioctl(oh->si_fd, PERF_EVENT_IOC_ENABLE,1);

        (void) ret;

}


void* thread_func(void* args) {
    long tid = (long) args;
    int i;
    int bp_counter, read_result, bp_total_count;
    tid_array[tid] = syscall(SYS_gettid);
    printf("thread %ld with OS id %d is waiting here\n", tid, tid_array[tid]);
    pthread_barrier_wait(&global_barrier);
    if(tid == 2) {
	    overflow_count = 0;
	   struct sigaction sa;
	   memset(&sa, 0, sizeof(struct sigaction));
           sa.sa_sigaction = our_handler;
           sa.sa_flags = SA_SIGINFO;

           if (sigaction( SIGIO, &sa, NULL) < 0) {
                fprintf(stderr,"Error setting up signal handler\n");
                exit(1);
           }


	   struct perf_event_attr pe;
	   memset(&pe,0,sizeof(struct perf_event_attr));
	   pe.type=PERF_TYPE_BREAKPOINT;
           pe.size=sizeof(struct perf_event_attr);
	   pe.config=0;
	   pe.bp_type=HW_BREAKPOINT_W;
	   pe.bp_addr=(unsigned long)&test_var1;
	   pe.bp_len=sizeof(int);
	   pe.sample_period=10000;
           pe.sample_type=PERF_SAMPLE_IP;
           pe.wakeup_events=1;
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
		printf("fd: %d is for thread %d\n", fds[i], i);
           	if (fds[i]<0) {
                	fprintf(stderr,"Error opening leader %llx\n",pe.config);
           	}

		fcntl(fds[i], F_SETFL, O_RDWR|O_NONBLOCK|O_ASYNC);
        	fcntl(fds[i], F_SETSIG, SIGIO);

		struct f_owner_ex owner;
  		owner.type = F_OWNER_TID;
  		owner.pid  = syscall(SYS_gettid);
        	fcntl(fds[i], F_SETOWN_EX, &owner);

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
	   printf("counter value: %d overflow_count: %d in thread %ld\n", bp_total_count, overflow_count, tid);
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
