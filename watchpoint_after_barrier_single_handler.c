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

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

int test_var1;
int test_var2;
int sender_counter;
int tid_array[NUM_THREADS];
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
	//kill(tid_array[4], SIGTSTP);
	printf("waiting here!!!!!!!!!!!\n");
	pthread_mutex_lock(&lock);
        ret=ioctl(oh->si_fd, PERF_EVENT_IOC_DISABLE, 0);
        printf("there is a signal from fd: %d handled by thread %ld\n", oh->si_fd, syscall(SYS_gettid));
	overflow_count++;

        ret=ioctl(oh->si_fd, PERF_EVENT_IOC_ENABLE,1);
	pthread_cond_signal(&cond);
	pthread_mutex_unlock(&lock);
	//kill(tid_array[4], SIGCONT);

        (void) ret;

}

static void insitu_handler(int signum,siginfo_t *oh, void *blah) {

	printf("waiting there by thread %ld\n", syscall(SYS_gettid));
	pthread_mutex_lock(&lock);
	sender_counter++;
	if (sender_counter > overflow_count) {
        	printf("Waiting on condition variable cond1\n");
        	pthread_cond_wait(&cond, &lock);
    	}
	pthread_mutex_unlock(&lock);
}


void* thread_func(void* args) {
    long tid = (long) args;
    int i;
    int bp_counter, read_result, bp_total_count, fd1, fd2;
    tid_array[tid] = syscall(SYS_gettid);
    printf("thread %ld with OS id %d is waiting here\n", tid, tid_array[tid]);
    pthread_barrier_wait(&global_barrier);
    if(tid == 2) {
	   overflow_count = 0;
	   struct sigaction sa;
	   memset(&sa, 0, sizeof(struct sigaction));
           sa.sa_sigaction = our_handler;
           sa.sa_flags = 0;

           if (sigaction( SIGUSR1, &sa, NULL) < 0) {
                fprintf(stderr,"Error setting up signal handler\n");
                exit(1);
           }

	   struct sigaction sa1;
           memset(&sa1, 0, sizeof(struct sigaction));
           sa1.sa_sigaction = insitu_handler;
           sa1.sa_flags = 0;

           if (sigaction( SIGUSR2, &sa1, NULL) < 0) {
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
	   pe.sample_period=1;
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

	   //for(int i = 0; i < NUM_THREADS; i++) {
	   fd1=perf_event_open(&pe, tid_array[4],-1,-1,0);
	   fd2=perf_event_open(&pe, tid_array[4],-1,-1,0);
	   printf("fd: %d is for thread %d\n", fd1, i);
           if (fd1<0) {
		   fprintf(stderr,"Error opening leader %llx\n",pe.config);
           }
	   fcntl(fd1, F_SETFL, O_RDWR|O_NONBLOCK|O_ASYNC);
	   fcntl(fd1, F_SETSIG, SIGUSR1);
	   
	   fcntl(fd2, F_SETFL, O_RDWR|O_NONBLOCK|O_ASYNC);
           fcntl(fd2, F_SETSIG, SIGUSR2);

	   struct f_owner_ex owner;
	   owner.type = F_OWNER_TID;
	   owner.pid  = syscall(SYS_gettid);
           fcntl(fd1, F_SETOWN_EX, &owner);

	   struct f_owner_ex owner1;
           owner1.type = F_OWNER_TID;
           owner1.pid  = tid_array[4];
           fcntl(fd2, F_SETOWN_EX, &owner1);

	   ioctl(fd1, PERF_EVENT_IOC_RESET, 0);
           int ret=ioctl(fd1, PERF_EVENT_IOC_ENABLE,0);
	   ioctl(fd2, PERF_EVENT_IOC_RESET, 0);
           ret=ioctl(fd2, PERF_EVENT_IOC_ENABLE,0);
	   //}
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
   printf("passed barrier 2 in thread %ld\n", tid);
   if (tid == 2 || tid == 4) {
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
	   //for(int i = 0; i < NUM_THREADS; i++) {
	   ioctl(fd1, PERF_EVENT_IOC_DISABLE,0);
	   read_result=read(fd1,&bp_counter,sizeof(long long));
	   //bp_total_count += bp_counter;
	   close(fd1);
	    //}
	   //printf("counter value: %d overflow_count: %d in thread %ld\n", bp_counter, overflow_count, tid);
    }
    if(tid == 2 || tid == 4)
	    printf("overflow_count: %d, sender_counter: %d, in thread %ld\n", overflow_count, sender_counter, tid);
    printf("passed barrier\n");

    return NULL;
}

int main() {
    pthread_t threads[NUM_THREADS];
    //struct barrier_and_id *barrier_tid_ptr = &barrier_tid;

    pthread_barrier_init(&global_barrier, NULL, NUM_THREADS);
    //"handler_counter = 0;
    sender_counter = 0;

    long i;
    for (i = 0; i < NUM_THREADS; i++) {
        pthread_create(&threads[i], NULL, thread_func, (void*)i);
    }

    for (i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}
