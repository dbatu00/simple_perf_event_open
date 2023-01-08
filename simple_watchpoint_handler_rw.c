/* overflow_signal.c  */
/* by Vince Weaver   vincent.weaver _at_ maine.edu */

#define _GNU_SOURCE 1

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

#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

#define MMAP_PAGES 8

size_t test_function(size_t a, size_t b) __attribute__((noinline));

size_t test_function(size_t a, size_t b) {

        size_t c;

        /* The time thing is there to keep the compiler */
        /* from optimizing this away.                   */

        c=a+b+rand();
        //if (!quiet) printf("\t\tFunction: %zd\n",c);
        return c;

}

static struct signal_counts {
	int in,out,msg,err,pri,hup,unknown,total;
} count = {0,0,0,0,0,0,0,0};

long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
         int cpu, int group_fd, unsigned long flags)
{
   int ret;

   ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
   return ret;
}

static int fd_wp;


static void our_handler(int signum,siginfo_t *oh, void *blah) {

        int ret;

        ret=ioctl(fd_wp, PERF_EVENT_IOC_DISABLE, 0);

		//switch not important
        switch(oh->si_code) {
                case POLL_IN:  count.in++;  break;
                case POLL_OUT: count.out++; break;
                case POLL_MSG: count.msg++; break;
                case POLL_ERR: count.err++; break;
                case POLL_PRI: count.pri++; break;
                case POLL_HUP: count.hup++; break;
                default: count.unknown++; break;
        }

        count.total++;

        ret=ioctl(fd_wp, PERF_EVENT_IOC_ENABLE,1);

        (void) ret;

}


int main(int argc, char** argv) {

	struct perf_event_attr pe_wp;
	struct sigaction sa;
	int read_result;
	int test_var = 0;
	long long bp_counter;

	void *our_mmap;

	void *address;

	address = test_function;
	memset(&sa, 0, sizeof(struct sigaction));
        sa.sa_sigaction = our_handler;
        sa.sa_flags = SA_SIGINFO;

        if (sigaction( SIGIO, &sa, NULL) < 0) {
                fprintf(stderr,"Error setting up signal handler\n");
                exit(1);
        }

	/* Create a sampled event and attach to child */

	memset(&pe_wp,0,sizeof(struct perf_event_attr));
	pe_wp.type=PERF_TYPE_BREAKPOINT;
	pe_wp.size=sizeof(struct perf_event_attr);
	pe_wp.config=0;
	pe_wp.bp_type=HW_BREAKPOINT_RW;
	pe_wp.bp_addr=(unsigned long)&test_var; // address to start of memory region(offset address) to monitor
	pe_wp.bp_len=sizeof(int); 				 // just set it to 8bytes?
	pe_wp.sample_period=1;
	pe_wp.sample_type=PERF_SAMPLE_IP;
	pe_wp.wakeup_events=1;
	pe_wp.disabled=1;
	pe_wp.exclude_kernel=1;
	pe_wp.exclude_hv=1;
	

	fd_wp=perf_event_open(&pe_wp,0,-1,-1,0);
	if (fd_wp<0) {
		fprintf(stderr,"Error opening leader %llx\n",pe_wp.config);
	}

	//our_mmap=mmap(NULL, (1+MMAP_PAGES)*getpagesize(),
	//		PROT_READ|PROT_WRITE, MAP_SHARED, fd_wp, 0);


        fcntl(fd_wp, F_SETFL, O_RDWR|O_NONBLOCK|O_ASYNC);
        fcntl(fd_wp, F_SETSIG, SIGIO);
        fcntl(fd_wp, F_SETOWN,getpid());

	ioctl(fd_wp, PERF_EVENT_IOC_RESET, 0);
	int ret=ioctl(fd_wp, PERF_EVENT_IOC_ENABLE,0);

	if (ret<0) {
		fprintf(stderr,"Error with PERF_EVENT_IOC_ENABLE of group leader: "
					"%d %s\n",errno,strerror(errno));
	}

	//for(int i = 0; i < 100000000; i++);
	for(int i=0;i<10000;i++) {
                //sum+=test_function(i,sum);
		test_var += i;
        }
	ioctl(fd_wp, PERF_EVENT_IOC_DISABLE,0);
	
	read_result=read(fd_wp,&bp_counter,sizeof(long long));
	close(fd_wp);

	printf("counter value: %lld, signal count: %d\n", bp_counter, count.total);
	/*count.total=count.in+count.hup;

	printf("Counts, using mmap buffer %p\n",our_mmap);
	printf("\tPOLL_IN : %d\n",count.in);
	printf("\tPOLL_OUT: %d\n",count.out);
	printf("\tPOLL_MSG: %d\n",count.msg);
	printf("\tPOLL_ERR: %d\n",count.err);
	printf("\tPOLL_PRI: %d\n",count.pri);
	printf("\tPOLL_HUP: %d\n",count.hup);
	printf("\tUNKNOWN : %d\n",count.unknown);

	if (count.total==0) {
		printf("No overflow events generated.\n");
	}

	if (count.in!=10) {
		printf("Unexpected POLL_IN count.\n");
	}

	if (count.hup!=0) {
		printf("POLL_HUP value %d, expected %d.\n",
					count.hup,10);
	}*/

	return 0;
}

