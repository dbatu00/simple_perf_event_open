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

#include "perf_barrier.h"

#define MMAP_PAGES 8
#define NUM_EVENTS 2

long long perf_mmap_read( void *our_mmap, int mmap_size,
                    long long prev_head,
		    int sample_type, int read_format);

long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
         int cpu, int group_fd, unsigned long flags)
{
   int ret;

   ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
   return ret;
}

static int fd1;
static int total;

static void our_handler(int signum,siginfo_t *oh, void *blah) {

        int ret;

        ret=ioctl(fd1, PERF_EVENT_IOC_DISABLE, 0);


        total++;

        ret=ioctl(fd1, PERF_EVENT_IOC_ENABLE,1);

        (void) ret;

}

int main(int argc, char** argv) {

	struct perf_event_attr pe;
	struct sigaction sa;

	void *our_mmap;

	memset(&sa, 0, sizeof(struct sigaction));
        sa.sa_sigaction = our_handler;
        sa.sa_flags = SA_SIGINFO;

        if (sigaction( SIGIO, &sa, NULL) < 0) {
                fprintf(stderr,"Error setting up signal handler\n");
                exit(1);
        }

	/* Create a sampled event and attach to child */

	memset(&pe,0,sizeof(struct perf_event_attr));

	pe.type=PERF_TYPE_RAW;
	pe.size=sizeof(struct perf_event_attr);
	pe.config=0x82d0;

	/* 1 million.  Tried 100k but that was too short on */
	/* faster machines, likely triggered overflow while */
	/* poll still was being handled?                    */
	pe.sample_period=100000;
	pe.sample_type=PERF_SAMPLE_IP;
	pe.read_format=PERF_FORMAT_GROUP|PERF_FORMAT_ID;
	pe.disabled=1;
	pe.pinned=1;
	pe.exclude_kernel=1;
	pe.exclude_hv=1;
	pe.watermark=0;
	pe.wakeup_events=4;
	pe.precise_ip=2;

	fd1=perf_event_open(&pe,0,-1,-1,0);
	if (fd1<0) {
		fprintf(stderr,"Error opening leader %llx\n",pe.config);
	}

	our_mmap=mmap(NULL, (1+MMAP_PAGES)*getpagesize(),
			PROT_READ|PROT_WRITE, MAP_SHARED, fd1, 0);


        fcntl(fd1, F_SETFL, O_RDWR|O_NONBLOCK|O_ASYNC);
        fcntl(fd1, F_SETSIG, SIGIO);
        fcntl(fd1, F_SETOWN,getpid());

	total = 0;
	ioctl(fd1, PERF_EVENT_IOC_RESET, 0);
	int ret=ioctl(fd1, PERF_EVENT_IOC_ENABLE,0);

	if (ret<0) {
		fprintf(stderr,"Error with PERF_EVENT_IOC_ENABLE of group leader: "
					"%d %s\n",errno,strerror(errno));
	}

	int sum = 0, val = 1;
	for(int i = 0; i < 200000000; i++) {
		__asm__ __volatile__ ("movl %1, %%ebx;"
                                "addl %%ebx, %0;"
                                : "=m" (sum)
                                : "r" (val)
                                : "%ebx");
	}
	
	close(fd1);
	fprintf(stderr, "number of samples: %d\n", total);	
	return 0;
}

