//use cpu number as tid
//check cpu
//one thread
//multithread


//in dolap 88 logical cores
//44 physical cores
//each physical core has its own set of debug registers
//when 2 threads run on a 

/* COMDETECTIVE

ComDetective tells each thread in a multithreaded program to configure their own PMU for 
detecting inter-thread communications of the program.
PMU's(performance monitoring unit of Precise Event Based Sampling) return information such
as effective address involved in a memory access that causes a threshold overflow (ex. 10000 loads) 
to the profiled programs threads using signals.
The samples are handled by the profiled thread.
This requires modifying the code of the monitored program.
The threads check a global table to see if another thread published the same address:
	if so, there is a communication and a communication matrix is updated
	if not, the address get published with a timestamp and publishing thread's ID.
	In both cases the thread selects a random address that was published by another thread to monitor 
	and arms its debug registers with the half of the cache line that the address belongs to.
	-Half because there are 4 debug registers per thread, a debug register holds 8 bytes and 
	a cache line is 64 bytes(4 x 8 / 64) 
	-Cache line becuase aimed granularity is cache line level inter-thread communication which is 
	a common slow-down factor
When a thread experiences a trap(accessing an address that is in one of their debug registers)
communication is reported.

ComDetective is built on HPC Tool Kit
*/

/* COMDETECTIVE RECONSTRUCTION FOR SUPERTWIN
In SuperTwin the monitored program cannot be changed thus, the monitored threads cant handle
their own samples and traps. 
In Intel processors that fall under the category of  Architectural Performance Monitoring Version 1
and upper versions, each logical thread can be assigned a set of PMUs and a set of debug registers.
To monitor a thread the CPU ID of the thread is required. This is done by passing the CPU ID's that
the multithreaded monitored program can run on to the profiling process. The threads should not change
CPUs (migrate to another CPU) during execution for accuracy. 
For each CPU ID passed, a profiler thread is created to configure the PMU's, debug registers and 
handle samples, traps. 
Each profiler thread: 
	Set two perf_event_attribute structs to monitor loads and stores.
	Make two perf_event_open system call (one for store, one for load) with the pid set to 0 and CPU 
	set to monitored CPU number. 
	Debug registers are configured similiarly at each sample.
	The address used to arm each debug register and the ID of the thread that published that address
	need to be kept to report communication properly.
	The operating system sees each logical core as a CPU thus, monitoring a CPU monitors the thread
	that runs on the CPU.
	Handles samples and traps as described in COMDETECTIVE
*/

/* some notes
When a process/thread receives a signal it jumps to the execution of the signal handler
PMU samples and trap activation notice are delivered to a process/thread via signals
If a thread experiences a sample/trap while its handling a signal, the execution can get broken
Ex: On a sample the thread arms its debug registers and keeps a record of the ID 
of the thread that published the address. As no information comes from traps other than activation
notice, recorded information is used to deduct which thread that the profiled thread communicated with.
If this scenario happens, the reported communication is wrong:
The thread receives a sample and arms its debug registers with the address that another thread published
(lets say T1).
The thread receives another sample and updates the thread ID variable with the ID of a thread that published
an address on the global board(lets say T2).
The thread receives a trap notice before re-arming its debug registers, the communication is reported
to be between monitored thread and T2 while it should've been between monitored thread and T1.
To overcome this, when a sample is received, the debug registers need to be disabled as the first thing 
Sample signals can also intervene so its best to disable both load and store PMUs when a sample is received

one debug register monitors one memory region(ex: address 10 to 18)
any access to that region activates the trap
get offset address(beginning of cache line) of monitored variable 
cache line = 64 bytes, each debug register 8 bytes x 4 registers 
																= 32 bytes 
																=> select 4 random regions to monitor
monitor the cache line because we are focused on
cache-line granularity inter-thread communication 

PMU & debug rx: 
there are 4 counters(PMUs) in a cpu 
	=> can monitor 4 events(not relevant as we monitor 2)
PMUs and debug registers are different hardware 
PMUs trigger interrupts, debug registers trigger traps
perf_event_open used for both PMUs and debug registers

no need to differentiate events(load/store) for debug register unlike PMU
as the profiling thread knows which address it armed a debug register with,
it can deduct what address caused an interrupt
*pe.bp_addr=(unsigned long)&test_var; // offset of cacheline of address to be monitored*

1) create watchpoint(debug register trapping) by perf event open
2) re-arm by using PERF_EVENT_IOC_MODIFY_ATTRIBUTES
*/

#define _GNU_SOURCE 1

//#include "test_utils.h"
//#include "perf_helpers.h"
//#include "matrix_multiply.h"
//#include "parse_record.h"
//#include "perf_event.h"
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
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include "perf_barrier.h"
#include <pthread.h>
#include <inttypes.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

#if defined(__x86_64__) || defined(__i386__) ||defined(__arm__)
#include <asm/perf_regs.h>
#endif

#define SAMPLE_PERIOD 1000000 // 100000 original value
							  // I usually select higher values to get less results so 
							  // that inspecting the output is easier


#define MMAP_DATA_SIZE 8

#define RAW_IBS_FETCH   1
#define RAW_IBS_OP      2

#define MMAP_PAGES 8

#define CACHE_LINE_SIZE 64

#define MAX_THREADS 20 // not used

#define NULL_TID_VALUE -1

typedef int TID_TYPE;

typedef enum {false, true} bool;

size_t test_function(size_t a, size_t b) __attribute__((noinline));

size_t test_function(size_t a, size_t b) {

        size_t c;

        /* The time thing is there to keep the compiler */
        /* from optimizing this away.                   */

        c=a+b+rand();
        //if (!quiet) printf("\t\tFunction: %zd\n",c);
        return c;

}

/* Global vars as I'm lazy */
static int count_total_store=0;
static int count_total_load=0;
static int count_total_allSignal=0;


static char *mmap_store; //mmaps are used to store information about samples
static char *mmap_load;  //file descriptor belonging to a perf event call needs 
						 //to be used as a variable for the sample
   						 // => each type of sample(load/store) requires its own mmap
						 //these need to be per thread


/* NOT USED
static char *mmap_wp; 
static char *mmap_storeList[MAX_THREADS]; 
static char *mmap_loadList[MAX_THREADS];
 */

static long sample_type; //decides what information is received on a sample
static long read_format;
static int quiet;
static long long prev_head_store;
static long long prev_head_load;
static int sum = 0, val = 1, unused = 5; //test variables that can be used to run 
										 //matrix multiplication assembly code below
int *ptr = &unused; //wp's need an address for the perf event attribute struct
					//wp's can be disabled before monitoring starts


static long long addr;  //global addr valuable that gets updated on a new sample
						//how it gets updated can be found by searching the comment below
						//memcpy(&addr,&data[offset],sizeof(long long));
						


static int fd_wp[4]; // 4 watchpoint file descriptors for 4 watchpoints of each thread
struct perf_event_attr pe_wp; //perf_event_attr is used in a perf event open call to configure PMU and dbg rx

/* NOT USED
static int process_id; //id of the process to be monitored
static pid_t pid;



static TID_TYPE thread_ids[MAX_THREADS];
static TID_TYPE sampleTid; //very risky because most use cases of sampleTID requires it to be an int


void init_thread_ids(){
    for(int i=0; i<MAX_THREADS; i++){
        thread_ids[i] = NULL_TID_VALUE; 
    }
}


bool threadUniqueCheck(TID_TYPE TID){
	bool unique = true;
	for(int i=0; i<MAX_THREADS; i++){
		if(TID == thread_ids[i])
		{
			unique = false;
		}
	}
	return unique;

}

void addThreadToList(TID_TYPE TID){
	for(int i=0; i<MAX_THREADS; i++)
	{
		if(thread_ids[i] == NULL_TID_VALUE) 
		{
			thread_ids[i] = TID;
			return;
		} 
    }
		
	printf("An error occured during addThreadToList function");
	

}

void printThreadList()
{	printf("Thread List:\t");
	for(int i=0; i<MAX_THREADS; i++)
	{
		printf("%d ", thread_ids[i]); //could cause an error if tid type is not int 
	}
	printf("\n-1 = empty\n");

}
*/

#define CHECK(x) ({int err = (x); \
if (err) { \
fprintf(stderr, "%s: Failed with %d on line %d of file %s\n", strerror(errno), err, __LINE__, __FILE__); \
exit(-1); }\
err;})



static long long get_first_cache_line_address(long long addr) //returns the offset address of a cache 
															  //line for a given address in that cache line
{
    return (addr & ~(CACHE_LINE_SIZE - 1));
}

struct validate_values {
        int pid;
        int tid;
        int events;
        unsigned long branch_low;
        unsigned long branch_high;
};

volatile sig_atomic_t stop;

void catch_sigint(int sig) {
    stop = 1;
}


int test_quiet(void) {

        if (getenv("TESTS_QUIET")!=NULL) return 1;
        return 0;
}



long long perf_mmap_read(
                void *our_mmap, int mmap_size, long long prev_head,
                int sample_type, int read_format, long long reg_mask,
                struct validate_values *validate,
                int quiet, int *events_read,
                int raw_type );



long perf_event_open(struct perf_event_attr *hw_event, 
					pid_t pid,
         			int cpu, 
					int group_fd, 
					unsigned long flags)
{
   int ret;

   ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
   return ret;
}




static struct signal_counts {
	int in,out,msg,err,pri,hup,unknown,total;
} count = {0,0,0,0,0,0,0,0};




static void wp_handler(int signum, siginfo_t *oh, void *blah) {
	printf("*********WP HANDLER - START*********\n");

    int ret;

	int fd = oh->si_fd; //fd number of the wp trap
						//When any process starts, then that process'
						//file descriptors table’s fd(file descriptor)
						//0, 1, 2 open automatically -geeksforgeeks.org
						//user opened file descriptors will have consequtive
						//numbers (3,4,5 etc.)
						//the fd is used to access and modify perf event open file

    ret=ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
	printf("\tWP = Disabled\n");
		

		//not important
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
		printf("\tcount total %d, trapped address: %llx\n", count.total, addr); // addr is for debugging purposes
																				// id of the publisher thread of 
																				// the address needs to be added

        //ret=ioctl(fd, PERF_EVENT_IOC_ENABLE,1);
		printf("**********WP HANDLER - END*********\n\n\n");

        (void) ret;

}


static void sample_handler(int signum, siginfo_t *info, void *uc) {

	// watchpoints need to be disabled here

	printf("*********SIGNAL HANDLER - START*********\n");
	int ret;

	int fd = info->si_fd; //by keeping track of fds as in load PMU fd is 3,
						  //store PMU fd is 4 etc. one can differentiate between
						  //load samples and store samplesx
						  
	

	ret=ioctl(fd, PERF_EVENT_IOC_DISABLE, 0); //both PMUs need to be disabled here
											  // and re-enabled later
	
	//printf("sum=%d, value=%d\n", sum, val);
	
	//function call above activates the perf_mmap_read function and outputs values 
	//specified in the sample_type to command line interface
	prev_head_store=perf_mmap_read(mmap_store,
							 MMAP_DATA_SIZE,
							 prev_head_store,
							 sample_type,read_format,
							 0, /* reg_mask */
							 NULL, /*validate */
							 quiet,
							 NULL, /* events read */
							 0);
	
	if(0) //its cumbersome to comment out perf_mmap_read function calls
	{

	//there needs to be different actions taken on a sample for store
	//samples and load samples, fd number can be used to differentiate them
	if(fd == 3){

		printf("store sample\n"); // sampled address = %p\n", &sum);	

		prev_head_store=perf_mmap_read(mmap_load,
							 MMAP_DATA_SIZE,
							 prev_head_store,
							 sample_type,read_format,
							 0, /* reg_mask */
							 NULL, /*validate */
							 quiet,
							 NULL, /* events read */
							 0);
		
		count_total_store++;
		printf("Store count= %d\n",count_total_store);
	}

	if(fd == 4){
		printf("load sample\n");// sampled address = %p\n\n", &val);

		prev_head_load=perf_mmap_read(mmap_load,
							 MMAP_DATA_SIZE,
							 prev_head_load,
							 sample_type,read_format,
							 0, /* reg_mask */
							 NULL, /*validate */
							 quiet,
							 NULL, /* events read */
							 0);
		/*NOT USED 
		if(threadUniqueCheck(sampleTid) == true){
			addThreadToList(sampleTid);
			printThreadList();
		}
		*/
		count_total_load++;
		printf("Load count= %d\n",count_total_load);
	}
	}
	
	count_total_allSignal++;
	printf("Sample count %d\n", count_total_allSignal);


	ret=ioctl(fd, PERF_EVENT_IOC_REFRESH, 1);

	
	/* RE ARM AND ACTIVATE WATCHPOINTS
	for(int i = 0; i<4; i++){
		//this selects first four 8-byte memory regions that belong to the cache line of the sampled address
		//it should be randomized
		long long bpAddr = (unsigned long long)get_first_cache_line_address(addr)+(i*8);
		pe_wp.bp_addr = bpAddr;
		//printf("Current address: 0x%llx\n", (unsigned long long)get_first_cache_line_address(addr)+(i*8));
		CHECK(ioctl(fd_wp[i], PERF_EVENT_IOC_MODIFY_ATTRIBUTES, (unsigned long) (&pe_wp)));
		printf("Debug register number %d armed with addr : %llx \n", i, bpAddr);
		ret=ioctl(fd_wp[i], PERF_EVENT_IOC_ENABLE,1);
		if(ret<0){
			printf("Problem enabling WP no: %d",i);
		}
		else{
			printf("\tWP no %d = Enabled\n",i);

		}
		

	}
	*/
	//Check if the re-arming call is successfull
	//CHECK(ioctl(fd_wp, PERF_EVENT_IOC_MODIFY_ATTRIBUTES, (unsigned long) (&pe_wp)));  

	printf("*********SIGNAL HANDLER - END*********\n\n\n");

	(void) ret;
	

}




int main(int argc, char **argv) 
{
	 

	int ret,ret2,ret_wp;
	int fd_store,fd_load;
	int mmap_pages=1+MMAP_DATA_SIZE;
	//long long bp_counter;
	//printf("sum address= %p, val address = %p\n", (void*)&sum, (void*)&val);

	char test_string[]="Testing pebs latency...";

	quiet=test_quiet();
	//init_thread_ids();

	
	//last value is PID of the process to be monitored
	//rest are the CPUs(logical cores(threads)) that the 
	//profiled process will be using
	printf("CPUs: ");
    for (int i = 1; i < argc; i++) {
        int value = atoi(argv[i]);
		if(i==argc-1)
		{
			printf("\nProfiled Process' ID: %d\n ", value);
			pid = (pid_t) value;

		}
		else{
			printf("%d ", value);
		}
        
    }

	if (!quiet) 
		printf("\nThis tests the intel PEBS latency.\n");

	
//create a thread for each cpu --pass only cpu info
//threads do their own config + handling
//global hash board


/////////////////////////PMU SIGACTION//////////////////////////
#pragma region
	struct sigaction sa;

	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_sigaction = sample_handler; //channel this signal to this handler
	sa.sa_flags = SA_SIGINFO;


	//first value(SIGIO) indicates which signal receiving channel this handler is assigned to
	if (sigaction( SIGIO, &sa, NULL) < 0) 
	{
			fprintf(stderr,"Error setting up signal handler\n");
			exit(1);
	}
#pragma endregion




////////////////////PMU PERF EVENT/////////////////////////////////
#pragma region
	struct perf_event_attr pe,pe_load; //pe should be pe_store 

	memset(&pe,0,sizeof(struct perf_event_attr));
	memset(&pe_load,0,sizeof(struct perf_event_attr));

	//information of these values will be received on a sample
	sample_type=PERF_SAMPLE_ADDR|PERF_SAMPLE_TID|PERF_SAMPLE_TIME|PERF_SAMPLE_CPU;
	

	//MEM_UOPS_RETIRED:ALL_STORES	 MEM_UOPS_RETIRED:ALL_LOADS 
 	//pe.config = 0x5382d0;			 pe.config = 0x5381d0;
	//pe.config = 0x82d0;			 pe.config = 0x81d0;	
	pe.config = 0x82d0; 			 pe_load.config = 0x81d0; //used to specify which event to count	
	

	//no need to change
	read_format=0;
	pe.sample_period=SAMPLE_PERIOD;  		pe_load.sample_period=SAMPLE_PERIOD; 
	pe.sample_type=sample_type;		 		pe_load.sample_type=sample_type;
    pe.type=PERF_TYPE_RAW;					pe_load.type=PERF_TYPE_RAW;
	pe.size=sizeof(struct perf_event_attr); pe_load.size=sizeof(struct perf_event_attr);
	pe.read_format=read_format; 	 		pe_load.read_format=read_format;
	pe.disabled=1;							pe_load.disabled=1;
	pe.pinned=1;					 		pe_load.pinned=1;
	pe.exclude_kernel=1;					pe_load.exclude_kernel=1;
	pe.exclude_hv=1; 						pe_load.exclude_hv=1;
	pe.wakeup_events=1;				 		pe_load.wakeup_events=1;
	pe.precise_ip=2;				 		pe_load.precise_ip=2;

	#pragma region perf event guide
	/*
	 pid == 0 and cpu == -1
              This measures the calling process/thread on any CPU.

       pid == 0 and cpu >= 0
              This measures the calling process/thread only when running
              on the specified CPU.

       pid > 0 and cpu == -1
              This measures the specified process/thread on any CPU.

       pid > 0 and cpu >= 0
              This measures the specified process/thread only when
              running on the specified CPU.

       pid == -1 and cpu >= 0
              This measures all processes/threads on the specified CPU.
              This requires CAP_PERFMON (since Linux 5.8) or
              CAP_SYS_ADMIN capability or a
              /proc/sys/kernel/perf_event_paranoid value of less than 1.

	*/
	#pragma endregion


	//below is creating fd couples for each CPU
	//this approach is wrong, a monitoring thread should be created for each CPU
	//the process needs to start a monitoring thread for each monitored thread
	for (int i = 1; i < argc-1; i++) // -1 bcus last value is pid
	{
        int value = atoi(argv[i]);
		
		fd_store=perf_event_open(&pe,-1,value,-1,0); // perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags);
		if (fd_store<0) 
		{
			if (!quiet) {
				fprintf(stderr,"Problem opening leader %s\n",
					strerror(errno));
				//test_fail(test_string);
			}
		}
		else{
				printf("fd_store = perf event open for cpu no: %d\n", value);
		}
	
		

		fd_load=perf_event_open(&pe_load,-1,value,-1,0); // call perf event open and assign
														 // it's fd number to an int variable
		if (fd_load<0) //-1 means file descriptor didnt open
		{
			if (!quiet) 
			{
				fprintf(stderr,"Problem opening leader %s\n",
					strerror(errno));
				//test_fail(test_string);
			}
		}
		else{printf("fd_load = perf event open for cpu no: %d\n", value);}
	
    
	//mmap is described in global declarations at top
	mmap_store=mmap(NULL, mmap_pages*4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd_store, 0);

	fcntl(fd_store, F_SETFL, O_RDWR|O_NONBLOCK|O_ASYNC); //no need to change
	fcntl(fd_store, F_SETSIG, SIGIO);					 //send this PMU's signals to SIGIO channel(?)
														 //this value and value of sigaction needs to match

	fcntl(fd_store, F_SETOWN, getpid());				 //this makes the PMU send signals to this calling process
														 //threads need to make this call with their own TID but the 
														 //way its done is different
														 //described in https://github.com/msasongko17/perf_event_modify_bp/blob/master/test3.c

	ioctl(fd_store, PERF_EVENT_IOC_RESET, 0);

	printf("fd store fcntl,ioctl calls done\n");

	mmap_load=mmap(NULL, mmap_pages*4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd_load, 0);

	fcntl(fd_load, F_SETFL, O_RDWR|O_NONBLOCK|O_ASYNC);
	fcntl(fd_load, F_SETSIG, SIGIO);
	fcntl(fd_load, F_SETOWN, getpid());

	ioctl(fd_load, PERF_EVENT_IOC_RESET, 0);

	printf("fd load fcntl,ioctl calls done\n");
	


	ret=ioctl(fd_store, PERF_EVENT_IOC_ENABLE,0);

	if (ret<0) {
		if (!quiet) {
			fprintf(stderr,"Error with PERF_EVENT_IOC_ENABLE "
				"of group leader: %d %s\n",
				errno,strerror(errno));
			exit(1);
		}
		else{
			printf("fd_store enabled\n");
		}
	}	


	ret2=ioctl(fd_load, PERF_EVENT_IOC_ENABLE,0);

	if (ret2<0) {
		if (!quiet) {
			fprintf(stderr,"Error with PERF_EVENT_IOC_ENABLE "
				"of group leader: %d %s\n",
				errno,strerror(errno));
			exit(1);
		}
		else{
			printf("fd_load enabled\n");
		}
	}

	}

	
#pragma endregion



/*
////////////////////PMU ACTIVATION + IOC/FCNTL///////////////
#pragma region 

	
	mmap_store=mmap(NULL, mmap_pages*4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd_store, 0);

	fcntl(fd_store, F_SETFL, O_RDWR|O_NONBLOCK|O_ASYNC);
	fcntl(fd_store, F_SETSIG, SIGIO);
	fcntl(fd_store, F_SETOWN, getpid());

	ioctl(fd_store, PERF_EVENT_IOC_RESET, 0);

	printf("fd store fcntl,ioctl calls done\n");

	mmap_load=mmap(NULL, mmap_pages*4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd_load, 0);

	fcntl(fd_load, F_SETFL, O_RDWR|O_NONBLOCK|O_ASYNC);
	fcntl(fd_load, F_SETSIG, SIGIO);
	fcntl(fd_load, F_SETOWN, getpid());

	ioctl(fd_load, PERF_EVENT_IOC_RESET, 0);

	printf("fd load fcntl,ioctl calls done\n");
	


	ret=ioctl(fd_store, PERF_EVENT_IOC_ENABLE,0);

	if (ret<0) {
		if (!quiet) {
			fprintf(stderr,"Error with PERF_EVENT_IOC_ENABLE "
				"of group leader: %d %s\n",
				errno,strerror(errno));
			exit(1);
		}
		else{
			printf("fd_store enabled\n");
		}
	}	


	ret2=ioctl(fd_load, PERF_EVENT_IOC_ENABLE,0);

	if (ret2<0) {
		if (!quiet) {
			fprintf(stderr,"Error with PERF_EVENT_IOC_ENABLE "
				"of group leader: %d %s\n",
				errno,strerror(errno));
			exit(1);
		}
		else{
			printf("fd_load enabled\n");
		}
	}

#pragma endregion
*/



/////////////////////////WP SIGACTION///////////////////////////
#pragma region

//similiar to PMU sigaction
struct sigaction sa_wp;

memset(&sa_wp, 0, sizeof(struct sigaction));
        sa_wp.sa_sigaction = wp_handler;
        sa_wp.sa_flags = SA_SIGINFO;

        if (sigaction( SIGRTMIN, &sa_wp, NULL) < 0) {
                fprintf(stderr,"Error setting up WATCHPOINT signal handler\n");
                exit(1);
        }

#pragma endregion




/////////////////////////WP PERF EVENT///////////////////////
#pragma region



memset(&pe_wp,0,sizeof(struct perf_event_attr));
	
	pe_wp.bp_type=HW_BREAKPOINT_RW; //activate breakpoint on both read and write events
	//pe_wp.bp_addr=(unsigned long)&sum;
	pe_wp.bp_addr=(unsigned long)&unused; //address 
	pe_wp.bp_len=sizeof(int); 			  //8bytes
	pe_wp.type=PERF_TYPE_BREAKPOINT;
	pe_wp.size=sizeof(struct perf_event_attr);
	pe_wp.config=0;
	pe_wp.sample_period=1;
	pe_wp.sample_type=PERF_SAMPLE_ADDR|PERF_SAMPLE_TID|PERF_SAMPLE_TIME|PERF_SAMPLE_CPU;
	pe_wp.wakeup_events=1;
	pe_wp.disabled=1;
	pe_wp.exclude_kernel=1;
	pe_wp.exclude_hv=1;

	//this needs to change for thread approach
	for(int i = 0; i<4; i++){
		fd_wp[i]=perf_event_open(&pe_wp, (pid_t)atoi(argv[1]),-1,-1,0); //(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags);
		if (fd_wp[i]<0) {
			fprintf(stderr,"Error opening leader %llx\n",pe_wp.config);
		}
		else{
			printf("File descriptor for WP no: %i opened\n",i);
		}

	}
	

	

#pragma endregion




////////////////////WP ACTIVATION + IOC/FCNTL///////////////
#pragma region

//mmap_wp=mmap(NULL, (1+MMAP_PAGES)*getpagesize(),
//				 PROT_READ|PROT_WRITE, MAP_SHARED, fd_wp, 0);
	for(int i = 0; i<4; i++){

	fcntl(fd_wp[i], F_SETFL, O_RDWR|O_NONBLOCK|O_ASYNC);
	fcntl(fd_wp[i], F_SETSIG, SIGRTMIN); //values can be SIGIO, SIGRTMIN, SIGRTMIN+1, SIGRTMIN+2, SIGRTMIN+3
										 //each wp signal should be sent through a different channel
										 //these values need to be matched with sigaction's value
	fcntl(fd_wp[i], F_SETOWN, getpid());
	

	ioctl(fd_wp[i], PERF_EVENT_IOC_RESET, 0);
	ret_wp=ioctl(fd_wp[i], PERF_EVENT_IOC_DISABLE,0);

	if (ret_wp<0) { fprintf(stderr,"Error with PERF_EVENT_IOC_DISABLE of one of the watchpoints: ""%d %s\n",errno,strerror(errno));}
	
	}






#pragma endregion

/*
////////////////////////////MATRIX///////////////////////////////
#pragma region
	printf("matrix multiplication\n\n");

	//naive_matrix_multiply(quiet);
		
	__asm__ __volatile__ (
	"movq $100000000, %%rcx;"
			"movl $1, %%ebx;"
			"loop0:;"
			"movl %%ebx, %0;"
			"movl %1, %%ebx;"
	"subq $1, %%rcx;"
			"cmpq $0, %%rcx;"
			"jne loop0;"
			: "=m" (sum)
			: "m" (val)
			: "%ebx", "%ecx");
	

#pragma endregion
*/



#pragma region clean up
while(1){
           sleep(1); 
        }

	ret=ioctl(fd_store, PERF_EVENT_IOC_REFRESH,0);
	printf("fd_store refresh\n");

	ret2=ioctl(fd_load, PERF_EVENT_IOC_REFRESH,0);
	printf("fd_load refresh\n");

	for(int i = 0; i<4; i++){
		ret2=ioctl(fd_wp[i], PERF_EVENT_IOC_REFRESH,0);
	

	}
	
	

	if (!quiet) 
		printf("Counts %d, using mmap store buffer %p\n",count_total_store,mmap_store);
	if (!quiet) 
		printf("Counts %d, using mmap load buffer %p\n",count_total_load,mmap_load);
    

	if (count_total_allSignal==0) 
	{
		if (!quiet) printf("No overflow events generated.\n");
		//test_fail(test_string);
	}
	

	munmap(mmap_store,mmap_pages*4096);
	munmap(mmap_load,mmap_pages*4096);

	close(fd_store);
	close(fd_load);
	for(int i = 0; i<4; i++){

	ioctl(fd_wp[i], PERF_EVENT_IOC_DISABLE,0);
	
	//read_result=read(fd_wp,&bp_counter,sizeof(long long));
	close(fd_wp[i]);
	}


	//test_pass(test_string);
#pragma endregion
		
        printf("Profiled program finished.\n");
	
	return 0;


}






















/* Urgh who designed this interface */
static int handle_struct_read_format(unsigned char *sample,
				     int read_format,
				     struct validate_values *validation,
				     int quiet) {

	int offset=0,i;

	if (read_format & PERF_FORMAT_GROUP) {
		long long nr,time_enabled,time_running;

		memcpy(&nr,&sample[offset],sizeof(long long));
		if (!quiet) printf("\t\tNumber: %lld ",nr);
		offset+=8;

		if (validation) {
			if (validation->events!=nr) {
				fprintf(stderr,"Error!  Wrong number "
						"of events %d != %lld\n",
						validation->events,nr);
			}
		}

		if (read_format & PERF_FORMAT_TOTAL_TIME_ENABLED) {
			memcpy(&time_enabled,&sample[offset],sizeof(long long));
			if (!quiet) printf("enabled: %lld ",time_enabled);
			offset+=8;
		}
		if (read_format & PERF_FORMAT_TOTAL_TIME_RUNNING) {
			memcpy(&time_running,&sample[offset],sizeof(long long));
			if (!quiet) printf("running: %lld ",time_running);
			offset+=8;
		}

		if (!quiet) printf("\n");

		for(i=0;i<nr;i++) {
			long long value, id;

			memcpy(&value,&sample[offset],sizeof(long long));
			if (!quiet) printf("\t\t\tValue: %lld ",value);
			offset+=8;

			if (read_format & PERF_FORMAT_ID) {
				memcpy(&id,&sample[offset],sizeof(long long));
				if (!quiet) printf("id: %lld ",id);
				offset+=8;
			}

			if (!quiet) printf("\n");
		}
	}
	else {

		long long value,time_enabled,time_running,id;

		memcpy(&value,&sample[offset],sizeof(long long));
		if (!quiet) printf("\t\tValue: %lld ",value);
		offset+=8;

		if (read_format & PERF_FORMAT_TOTAL_TIME_ENABLED) {
			memcpy(&time_enabled,&sample[offset],sizeof(long long));
			if (!quiet) printf("enabled: %lld ",time_enabled);
			offset+=8;
		}
		if (read_format & PERF_FORMAT_TOTAL_TIME_RUNNING) {
			memcpy(&time_running,&sample[offset],sizeof(long long));
			if (!quiet) printf("running: %lld ",time_running);
			offset+=8;
		}
		if (read_format & PERF_FORMAT_ID) {
			memcpy(&id,&sample[offset],sizeof(long long));
			if (!quiet) printf("id: %lld ",id);
			offset+=8;
		}
		if (!quiet) printf("\n");
	}

	return offset;
}

#if defined(__x86_64__)

#define NUM_REGS	PERF_REG_X86_64_MAX
static char reg_names[NUM_REGS][8]=
			{"RAX","RBX","RCX","RDX","RSI","RDI","RBP","RSP",
			 "RIP","RFLAGS","CS","SS","DS","ES","FS","GS",
			 "R8","R9","R10","R11","R12","R13","R14","R15"};


#elif defined(__i386__)

#define NUM_REGS	PERF_REG_X86_32_MAX
static char reg_names[PERF_REG_X86_32_MAX][8]=
			{"EAX","EBX","ECX","EDX","ESI","EDI","EBP","ESP",
			 "EIP","EFLAGS","CS","SS","DS","ES","FS","GS"};

#elif defined(__arm__)

#define NUM_REGS	PERF_REG_ARM_MAX
static char reg_names[PERF_REG_ARM_MAX][8]=
			{"R0","R1","R2","R3","R4","R5","R6","R7",
			 "R8","R9","R10","FP","IP","SP","LR","PC"};

#else

#define NUM_REGS 0

static char reg_names[1][8]={"NONE!"};

#endif



static int print_regs(int quiet,long long abi,long long reg_mask,
		unsigned char *data) {

	int return_offset=0;
	int num_regs=NUM_REGS;
	int i;
	unsigned long long reg_value;

	if (!quiet) printf("\t\tReg mask %llx\n",reg_mask);
	for(i=0;i<64;i++) {
		if (reg_mask&1ULL<<i) {
			if (!quiet) {
				memcpy(&reg_value,&data[return_offset],8);
				if (i<num_regs) {
					printf("\t\t%s : ",reg_names[i]);
				}
				else {
					printf("\t\t??? : ");
				}

				printf("%llx\n",reg_value);
			}
			return_offset+=8;
		}
	}

	return return_offset;
}


static int dump_raw_ibs_fetch(unsigned char *data, int size) {

	unsigned long long *msrs;
	unsigned int *leftover;

	msrs=(unsigned long long *)(data+4);
	leftover=(unsigned int *)(data);

	printf("\t\tHeader: %x\n",leftover[0]);
	printf("\t\tMSR IBS_FETCH_CONTROL %llx\n",msrs[0]);
	printf("\t\t\tIBS_RAND_EN: %d\n",!!(msrs[0]&1ULL<<57));
	printf("\t\t\tL2 iTLB Miss: %d\n",!!(msrs[0]&1ULL<<56));
	printf("\t\t\tL1 iTLB Miss: %d\n",!!(msrs[0]&1ULL<<55));
	printf("\t\t\tL1TLB page size: ");
	switch( (msrs[0]>>53)&0x3) {
		case 0:	printf("4kB\n"); break;
		case 1:	printf("2MB\n"); break;
		case 2: printf("1GB\n"); break;
		default:	printf("Resreved\n"); break;
	}

	printf("\t\t\tFetch Physical Address Valid: %d\n",!!(msrs[0]&1ULL<<52));
	printf("\t\t\ticache miss: %d\n",!!(msrs[0]&1ULL<<51));
	printf("\t\t\tInstruction Fetch Complete: %d\n",!!(msrs[0]&1ULL<<50));
	printf("\t\t\tInstruction Fetch Valid: %d\n",!!(msrs[0]&1ULL<<49));
	printf("\t\t\tInstruction Fetch Enabled: %d\n",!!(msrs[0]&1ULL<<48));
	printf("\t\t\tInstruction Fetch Latency: %lld\n",((msrs[0]>>32)&0xffff));
	printf("\t\t\tInstruction Fetch Count: %lld\n",((msrs[0]>>16)&0xffff)<<4);
	printf("\t\t\tInstruction Fetch Max Count: %lld\n",(msrs[0]&0xffff)<<4);

	printf("\t\tMSR IBS_FETCH_LINEAR_ADDRESS %llx\n",msrs[1]);
	printf("\t\tMSR IBS_FETCH_PHYSICAL_ADDRESS %llx\n",msrs[2]);
	if (size>24) {
		printf("\t\tMSR IBS_BRTARGET %llx\n",msrs[3]);
	}
	return 0;
}

static int dump_raw_ibs_op(unsigned char *data, int size) {

	unsigned long long *msrs;
	unsigned int *leftover;

	msrs=(unsigned long long *)(data+4);
	leftover=(unsigned int *)(data);

	printf("\t\tHeader: %x\n",leftover[0]);
	printf("\t\tMSR IBS_EXECUTION_CONTROL %llx\n",msrs[0]);
	printf("\t\t\tIbsOpCurCnt: %lld\n",((msrs[0]>>32)&0x3ffffff));
	printf("\t\t\tIBS OpCntCtl: %d\n",!!(msrs[0]&1ULL<<19));
	printf("\t\t\tIBS OpVal: %d\n",!!(msrs[0]&1ULL<<18));
	printf("\t\t\tIBS OpEn: %d\n",!!(msrs[0]&1ULL<<17));
	printf("\t\t\tIbsOpMaxCnt: %lld\n",((msrs[0]&0xffff)<<4) |
				(msrs[0]&0x3f00000));

	printf("\t\tMSR IBS_OP_LOGICAL_ADDRESS %llx\n",msrs[1]);

	printf("\t\tMSR IBS_OP_DATA %llx\n",msrs[2]);
	printf("\t\t\tRIP Invalid: %d\n",!!(msrs[2]&1ULL<<38));
	printf("\t\t\tBranch Retired: %d\n",!!(msrs[2]&1ULL<<37));
	printf("\t\t\tBranch Mispredicted: %d\n",!!(msrs[2]&1ULL<<36));
	printf("\t\t\tBranch Taken: %d\n",!!(msrs[2]&1ULL<<35));
	printf("\t\t\tReturn uop: %d\n",!!(msrs[2]&1ULL<<34));
	printf("\t\t\tMispredicted Return uop: %d\n",!!(msrs[2]&1ULL<<33));
	printf("\t\t\tTag to Retire Cycles: %lld\n",(msrs[2]>>16)&0xffff);
	printf("\t\t\tCompletion to Retire Cycles: %lld\n",msrs[2]&0xffff);

	printf("\t\tMSR IBS_OP_DATA2 (Northbridge) %llx\n",msrs[3]);
	printf("\t\t\tCache Hit State: %c\n",(msrs[3]&1ULL<<5)?'O':'M');
	printf("\t\t\tRequest destination node: %s\n",
		(msrs[3]&1ULL<<4)?"Same":"Different");
	printf("\t\t\tNorthbridge data source: ");
	switch(msrs[3]&0x7) {
		case 0:	printf("No valid status\n"); break;
		case 1: printf("L3\n"); break;
		case 2: printf("Cache from another compute unit\n"); break;
		case 3: printf("DRAM\n"); break;
		case 4: printf("Reserved remote cache\n"); break;
		case 5: printf("Reserved\n"); break;
		case 6: printf("Reserved\n"); break;
		case 7: printf("Other: MMIO/config/PCI/APIC\n"); break;
	}

	printf("\t\tMSR IBS_OP_DATA3 (cache) %llx\n",msrs[4]);
	printf("\t\t\tData Cache Miss Latency: %lld\n",
		(msrs[4]>>32)&0xffff);
	printf("\t\t\tL2TLB data hit in 1GB page: %d\n",
		!!(msrs[4]&1ULL<<19));
	printf("\t\t\tData cache physical addr valid: %d\n",
		!!(msrs[4]&1ULL<<18));
	printf("\t\t\tData cache linear addr valid: %d\n",
		!!(msrs[4]&1ULL<<17));
	printf("\t\t\tMAB hit: %d\n",
		!!(msrs[4]&1ULL<<16));
	printf("\t\t\tData cache locked operation: %d\n",
		!!(msrs[4]&1ULL<<15));
	printf("\t\t\tUncachable memory operation: %d\n",
		!!(msrs[4]&1ULL<<14));
	printf("\t\t\tWrite-combining memory operation: %d\n",
		!!(msrs[4]&1ULL<<13));
	printf("\t\t\tData forwarding store to load canceled: %d\n",
		!!(msrs[4]&1ULL<<12));
	printf("\t\t\tData forwarding store to load operation: %d\n",
		!!(msrs[4]&1ULL<<11));
	printf("\t\t\tBank conflict on load operation: %d\n",
		!!(msrs[4]&1ULL<<9));
	printf("\t\t\tMisaligned access: %d\n",
		!!(msrs[4]&1ULL<<8));
	printf("\t\t\tData cache miss: %d\n",
		!!(msrs[4]&1ULL<<7));
	printf("\t\t\tData cache L2TLB hit in 2M: %d\n",
		!!(msrs[4]&1ULL<<6));
	printf("\t\t\tData cache L2TLB hit in 1G: %d\n",
		!!(msrs[4]&1ULL<<5));
	printf("\t\t\tData cache L1TLB hit in 2M: %d\n",
		!!(msrs[4]&1ULL<<4));
	printf("\t\t\tData cache L2TLB miss: %d\n",
		!!(msrs[4]&1ULL<<3));
	printf("\t\t\tData cache L1TLB miss: %d\n",
		!!(msrs[4]&1ULL<<2));
	printf("\t\t\tOperation is a store: %d\n",
		!!(msrs[4]&1ULL<<1));
	printf("\t\t\tOperation is a load: %d\n",
		!!(msrs[4]&1ULL<<0));

	if (msrs[4]&1ULL<<17) {
		printf("\t\tMSR IBS_DC_LINEAR_ADDRESS %llx\n",msrs[5]);
	}
	if (msrs[4]&1ULL<<18) {
		printf("\t\tMSR IBS_DC_PHYSICAL_ADDRESS %llx\n",msrs[6]);
	}

	if (size>64) {
		printf("\t\tMSR IBS_OP_DATA4 %llx\n",msrs[7]);
	}
	return 0;
}

static int debug=0;

long long perf_mmap_read( void *our_mmap, int mmap_size,
			long long prev_head,
			int sample_type, int read_format, long long reg_mask,
			struct validate_values *validate,
			int quiet, int *events_read,
			int raw_type ) {

	printf("this is perf_mmap_read\n");
	struct perf_event_mmap_page *control_page = our_mmap;
	long long head,offset;
	int i,size;
	long long bytesize,prev_head_wrap;

	unsigned char *data;

	void *data_mmap=our_mmap+getpagesize();

	if (mmap_size==0) return 0;

	if (control_page==NULL) {
		fprintf(stderr,"ERROR mmap page NULL\n");
		return -1;
	}

	head=control_page->data_head;
	rmb(); /* Must always follow read of data_head */

	size=head-prev_head;

	//if (debug) {
		printf("Head: %lld Prev_head=%lld\n",head,prev_head);
		printf("%d new bytes\n",size);
	//}

	bytesize=mmap_size*getpagesize();

	if (size>bytesize) {
		printf("error!  we overflowed the mmap buffer %d>%lld bytes\n",
			size,bytesize);
	}

	data=malloc(bytesize);
	if (data==NULL) {
		return -1;
	}

	if (debug) {
		printf("Allocated %lld bytes at %p\n",bytesize,data);
	}

	prev_head_wrap=prev_head%bytesize;

	if (debug) {
		printf("Copying %lld bytes from (%p)+%lld to (%p)+%d\n",
			  bytesize-prev_head_wrap,data_mmap,prev_head_wrap,data,0);
	}

	memcpy(data,(unsigned char*)data_mmap + prev_head_wrap,
		bytesize-prev_head_wrap);

	if (debug) {
		printf("Copying %lld bytes from %d to %lld\n",
			prev_head_wrap,0,bytesize-prev_head_wrap);
	}

	memcpy(data+(bytesize-prev_head_wrap),(unsigned char *)data_mmap,
		prev_head_wrap);

	struct perf_event_header *event;


	offset=0;
	if (events_read) *events_read=0;

	while(offset<size) {

		if (debug) printf("Offset %lld Size %d\n",offset,size);
		event = ( struct perf_event_header * ) & data[offset];

		/********************/
		/* Print event Type */
		/********************/

		if (!quiet) {
			switch(event->type) {
				case PERF_RECORD_MMAP:
					printf("PERF_RECORD_MMAP");
					break;
				case PERF_RECORD_LOST:
					printf("PERF_RECORD_LOST");
					break;
				case PERF_RECORD_COMM:
					printf("PERF_RECORD_COMM");
					break;
				case PERF_RECORD_EXIT:
					printf("PERF_RECORD_EXIT");
					break;
				case PERF_RECORD_THROTTLE:
					printf("PERF_RECORD_THROTTLE");
					break;
				case PERF_RECORD_UNTHROTTLE:
					printf("PERF_RECORD_UNTHROTTLE");
					break;
				case PERF_RECORD_FORK:
					printf("PERF_RECORD_FORK");
					break;
				case PERF_RECORD_READ:
					printf("PERF_RECORD_READ");
					break;
				case PERF_RECORD_SAMPLE:
					printf("PERF_RECORD_SAMPLE [%x]",sample_type);
					break;
				case PERF_RECORD_MMAP2:
					printf("PERF_RECORD_MMAP2");
					break;
				case PERF_RECORD_AUX:
					printf("PERF_RECORD_AUX");
					break;
				case PERF_RECORD_ITRACE_START:
					printf("PERF_RECORD_ITRACE_START");
					break;
				case PERF_RECORD_LOST_SAMPLES:
					printf("PERF_RECORD_LOST_SAMPLES");
					break;
				case PERF_RECORD_SWITCH:
					printf("PERF_RECORD_SWITCH");
					break;
				case PERF_RECORD_SWITCH_CPU_WIDE:
					printf("PERF_RECORD_SWITCH_CPU_WIDE");
					break;
				default: printf("UNKNOWN %d",event->type);
					break;
			}

			printf(", MISC=%d (",event->misc);
			switch(event->misc & PERF_RECORD_MISC_CPUMODE_MASK) {
				case PERF_RECORD_MISC_CPUMODE_UNKNOWN:
					printf("PERF_RECORD_MISC_CPUMODE_UNKNOWN"); break; 
				case PERF_RECORD_MISC_KERNEL:
					printf("PERF_RECORD_MISC_KERNEL"); break;
				case PERF_RECORD_MISC_USER:
					printf("PERF_RECORD_MISC_USER"); break;
				case PERF_RECORD_MISC_HYPERVISOR:
					printf("PERF_RECORD_MISC_HYPERVISOR"); break;
				case PERF_RECORD_MISC_GUEST_KERNEL:
					printf("PERF_RECORD_MISC_GUEST_KERNEL"); break;
				case PERF_RECORD_MISC_GUEST_USER:
					printf("PERF_RECORD_MISC_GUEST_USER"); break;
				default:
					printf("Unknown %d!\n",event->misc); break;
			}

			/* All three have the same value */
			if (event->misc & PERF_RECORD_MISC_MMAP_DATA) {
				if (event->type==PERF_RECORD_MMAP) {
					printf(",PERF_RECORD_MISC_MMAP_DATA ");
				}
				else if (event->type==PERF_RECORD_COMM) {
					printf(",PERF_RECORD_MISC_COMM_EXEC ");
				}
				else if ((event->type==PERF_RECORD_SWITCH) ||
					(event->type==PERF_RECORD_SWITCH_CPU_WIDE)) {
					printf(",PERF_RECORD_MISC_SWITCH_OUT ");
				}
				else {
					printf("UNKNOWN ALIAS!!! ");
				}
			}


			if (event->misc & PERF_RECORD_MISC_EXACT_IP) {
				printf(",PERF_RECORD_MISC_EXACT_IP ");
			}

			if (event->misc & PERF_RECORD_MISC_EXT_RESERVED) {
				printf(",PERF_RECORD_MISC_EXT_RESERVED ");
			}

			printf("), Size=%d\n",event->size);
		}

		offset+=8; /* skip header */

		/***********************/
		/* Print event Details */
		/***********************/

		switch(event->type) {

		/* Lost */
		case PERF_RECORD_LOST: {
			long long id,lost;
			memcpy(&id,&data[offset],sizeof(long long));
			if (!quiet) printf("\tID: %lld\n",id);
			offset+=8;
			memcpy(&lost,&data[offset],sizeof(long long));
			if (!quiet) printf("\tLOST: %lld\n",lost);
			offset+=8;
			}
			break;

		/* COMM */
		case PERF_RECORD_COMM: {
			int pid,tid,string_size;
			char *string;

			memcpy(&pid,&data[offset],sizeof(int));
			if (!quiet) printf("\tPID: %d\n",pid);
			offset+=4;
			memcpy(&tid,&data[offset],sizeof(int));
			if (!quiet) printf("\tTID: %d\n",tid);
			offset+=4;

			/* FIXME: sample_id handling? */

			/* two ints plus the 64-bit header */
			string_size=event->size-16;
			string=calloc(string_size,sizeof(char));
			memcpy(string,&data[offset],string_size);
			if (!quiet) printf("\tcomm: %s\n",string);
			offset+=string_size;
			if (string) free(string);
			}
			break;

		/* Fork */
		case PERF_RECORD_FORK: {
			int pid,ppid,tid,ptid;
			long long fork_time;

			memcpy(&pid,&data[offset],sizeof(int));
			if (!quiet) printf("\tPID: %d\n",pid);
			offset+=4;
			memcpy(&ppid,&data[offset],sizeof(int));
			if (!quiet) printf("\tPPID: %d\n",ppid);
			offset+=4;
			memcpy(&tid,&data[offset],sizeof(int));
			if (!quiet) printf("\tTID: %d\n",tid);
			offset+=4;
			memcpy(&ptid,&data[offset],sizeof(int));
			if (!quiet) printf("\tPTID: %d\n",ptid);
			offset+=4;
			memcpy(&fork_time,&data[offset],sizeof(long long));
			if (!quiet) printf("\tTime: %lld\n",fork_time);
			offset+=8;
			}
			break;

		/* mmap */
		case PERF_RECORD_MMAP: {
			int pid,tid,string_size;
			long long address,len,pgoff;
			char *filename;

			memcpy(&pid,&data[offset],sizeof(int));
			if (!quiet) printf("\tPID: %d\n",pid);
			offset+=4;
			memcpy(&tid,&data[offset],sizeof(int));
			if (!quiet) printf("\tTID: %d\n",tid);
			offset+=4;
			memcpy(&address,&data[offset],sizeof(long long));
			if (!quiet) printf("\tAddress: %llx\n",address);
			offset+=8;
			memcpy(&len,&data[offset],sizeof(long long));
			if (!quiet) printf("\tLength: %llx\n",len);
			offset+=8;
			memcpy(&pgoff,&data[offset],sizeof(long long));
			if (!quiet) printf("\tPage Offset: %llx\n",pgoff);
			offset+=8;

			string_size=event->size-40;
			filename=calloc(string_size,sizeof(char));
			memcpy(filename,&data[offset],string_size);
			if (!quiet) printf("\tFilename: %s\n",filename);
			offset+=string_size;
			if (filename) free(filename);

			}
			break;

		/* mmap2 */
		case PERF_RECORD_MMAP2: {
			int pid,tid,string_size;
			long long address,len,pgoff;
			int major,minor;
			long long ino,ino_generation;
			int prot,flags;
			char *filename;

			memcpy(&pid,&data[offset],sizeof(int));
			if (!quiet) printf("\tPID: %d\n",pid);
			offset+=4;
			memcpy(&tid,&data[offset],sizeof(int));
			if (!quiet) printf("\tTID: %d\n",tid);
			offset+=4;
			memcpy(&address,&data[offset],sizeof(long long));
			if (!quiet) printf("\tAddress: %llx\n",address);
			offset+=8;
			memcpy(&len,&data[offset],sizeof(long long));
			if (!quiet) printf("\tLength: %llx\n",len);
			offset+=8;
			memcpy(&pgoff,&data[offset],sizeof(long long));
			if (!quiet) printf("\tPage Offset: %llx\n",pgoff);
			offset+=8;
			memcpy(&major,&data[offset],sizeof(int));
			if (!quiet) printf("\tMajor: %d\n",major);
			offset+=4;
			memcpy(&minor,&data[offset],sizeof(int));
			if (!quiet) printf("\tMinor: %d\n",minor);
			offset+=4;
			memcpy(&ino,&data[offset],sizeof(long long));
			if (!quiet) printf("\tIno: %llx\n",ino);
			offset+=8;
			memcpy(&ino_generation,&data[offset],sizeof(long long));
			if (!quiet) printf("\tIno generation: %llx\n",ino_generation);
			offset+=8;
			memcpy(&prot,&data[offset],sizeof(int));
			if (!quiet) printf("\tProt: %d\n",prot);
			offset+=4;
			memcpy(&flags,&data[offset],sizeof(int));
			if (!quiet) printf("\tFlags: %d\n",flags);
			offset+=4;

			string_size=event->size-72;
			filename=calloc(string_size,sizeof(char));
			memcpy(filename,&data[offset],string_size);
			if (!quiet) printf("\tFilename: %s\n",filename);
			offset+=string_size;
			if (filename) free(filename);

			}
			break;

		/* Exit */
		case PERF_RECORD_EXIT: {
			int pid,ppid,tid,ptid;
			long long fork_time;

			memcpy(&pid,&data[offset],sizeof(int));
			if (!quiet) printf("\tPID: %d\n",pid);
			offset+=4;
			memcpy(&ppid,&data[offset],sizeof(int));
			if (!quiet) printf("\tPPID: %d\n",ppid);
			offset+=4;
			memcpy(&tid,&data[offset],sizeof(int));
			if (!quiet) printf("\tTID: %d\n",tid);
			offset+=4;
			memcpy(&ptid,&data[offset],sizeof(int));
			if (!quiet) printf("\tPTID: %d\n",ptid);
			offset+=4;
			memcpy(&fork_time,&data[offset],sizeof(long long));
			if (!quiet) printf("\tTime: %lld\n",fork_time);
			offset+=8;
			}
			break;

		/* Throttle/Unthrottle */
		case PERF_RECORD_THROTTLE:
		case PERF_RECORD_UNTHROTTLE: {
			long long throttle_time,id,stream_id;

			memcpy(&throttle_time,&data[offset],sizeof(long long));
			if (!quiet) printf("\tTime: %lld\n",throttle_time);
			offset+=8;
			memcpy(&id,&data[offset],sizeof(long long));
			if (!quiet) printf("\tID: %lld\n",id);
			offset+=8;
			memcpy(&stream_id,&data[offset],sizeof(long long));
			if (!quiet) printf("\tStream ID: %lld\n",stream_id);
			offset+=8;

			}
			break;

		/* Sample */
		case PERF_RECORD_SAMPLE:
			if (sample_type & PERF_SAMPLE_IP) {
				long long ip;
				memcpy(&ip,&data[offset],sizeof(long long));
				if (!quiet) printf("\tPERF_SAMPLE_IP, IP: %llx\n",ip);
				offset+=8;
			}
			if (sample_type & PERF_SAMPLE_TID) {
				int pid, tid;

				memcpy(&pid,&data[offset],sizeof(int));
				memcpy(&tid,&data[offset+4],sizeof(int));
				sampleTid = tid;
				

				if (validate) {
					if (validate->pid!=pid) {
						fprintf(stderr,"Error, pid %d != %d\n",
							validate->pid,pid);
					}
				}

				if (!quiet) {
					printf("\tPERF_SAMPLE_TID, pid: %d  tid %d\n",pid,tid);
				}
				offset+=8;
			}

			if (sample_type & PERF_SAMPLE_TIME) {
				long long time;
				memcpy(&time,&data[offset],sizeof(long long));
				if (!quiet) printf("\tPERF_SAMPLE_TIME, time: %lld\n",time);
				offset+=8;
			}
			if (sample_type & PERF_SAMPLE_ADDR) {
				//long long addr; --made global 
				memcpy(&addr,&data[offset],sizeof(long long));
				if (!quiet) printf("\tPERF_SAMPLE_ADDR, addr: %llx\n",addr);
				offset+=8;
			}
			if (sample_type & PERF_SAMPLE_ID) {
				long long sample_id;
				memcpy(&sample_id,&data[offset],sizeof(long long));
				if (!quiet) printf("\tPERF_SAMPLE_ID, sample_id: %lld\n",sample_id);
				offset+=8;
			}
			if (sample_type & PERF_SAMPLE_STREAM_ID) {
				long long sample_stream_id;
				memcpy(&sample_stream_id,&data[offset],sizeof(long long));
				if (!quiet) {
					printf("\tPERF_SAMPLE_STREAM_ID, sample_stream_id: %lld\n",sample_stream_id);
				}
				offset+=8;
			}
			if (sample_type & PERF_SAMPLE_CPU) {
				int cpu, res;
				memcpy(&cpu,&data[offset],sizeof(int));
				memcpy(&res,&data[offset+4],sizeof(int));
				if (!quiet) printf("\tPERF_SAMPLE_CPU, cpu: %d  res %d\n",cpu,res);
				offset+=8;
			}
			if (sample_type & PERF_SAMPLE_PERIOD) {
				long long period;
				memcpy(&period,&data[offset],sizeof(long long));
				if (!quiet) printf("\tPERF_SAMPLE_PERIOD, period: %lld\n",period);
				offset+=8;
			}
			if (sample_type & PERF_SAMPLE_READ) {
				int length;

				if (!quiet) printf("\tPERF_SAMPLE_READ, read_format\n");
				length=handle_struct_read_format(&data[offset],
						read_format,
						validate,quiet);
				if (length>=0) offset+=length;
			}
			if (sample_type & PERF_SAMPLE_CALLCHAIN) {
				long long nr,ip;
				memcpy(&nr,&data[offset],sizeof(long long));
				if (!quiet) printf("\tPERF_SAMPLE_CALLCHAIN, callchain length: %lld\n",nr);
				offset+=8;

				for(i=0;i<nr;i++) {
					memcpy(&ip,&data[offset],sizeof(long long));
					if (!quiet) printf("\t\t ip[%d]: %llx\n",i,ip);
					offset+=8;
				}
			}
			if (sample_type & PERF_SAMPLE_RAW) {
				int size;

				memcpy(&size,&data[offset],sizeof(int));
				if (!quiet) printf("\tPERF_SAMPLE_RAW, Raw length: %d\n",size);
				offset+=4;

				if (!quiet) {
					if (raw_type==RAW_IBS_FETCH) {
						dump_raw_ibs_fetch(&data[offset],size);
					}
					else if (raw_type==RAW_IBS_OP) {
						dump_raw_ibs_op(&data[offset],size);
					}
					else {
						printf("\t\t");
						for(i=0;i<size;i++) {
							printf("%d ",data[offset+i]);
						}
						printf("\n");
					}
				}
				offset+=size;
			}

			if (sample_type & PERF_SAMPLE_BRANCH_STACK) {
				long long bnr;
				memcpy(&bnr,&data[offset],sizeof(long long));
				if (!quiet) {
					printf("\tPERF_SAMPLE_BRANCH_STACK, branch_stack entries: %lld\n",bnr);
				}
				offset+=8;

				for(i=0;i<bnr;i++) {
					long long from,to,flags;

					/* From value */
					memcpy(&from,&data[offset],sizeof(long long));
					offset+=8;

					/* Could be more complete here */
					if (validate) {
						if (from < validate->branch_low) {
							fprintf(stderr,"Error! branch out of bounds!\n");
						}
					}


					/* To Value */
					memcpy(&to,&data[offset],sizeof(long long));
					offset+=8;
					if (!quiet) {
						printf("\t\t lbr[%d]: %llx %llx ",
							i,from,to);
		 			}

					/* Flags */
					memcpy(&flags,&data[offset],sizeof(long long));
					offset+=8;

					if (!quiet) {
						if (flags==0) printf("0");

						if (flags&1) {
							printf("MISPREDICTED ");
							flags&=~2;
						}

						if (flags&2) {
							printf("PREDICTED ");
							flags&=~2;
						}

						if (flags&4) {
							printf("IN_TRANSACTION ");
							flags&=~4;
						}

						if (flags&8) {
							printf("TRANSACTION_ABORT ");
							flags&=~8;
						}
						printf("\n");
					}
	      			}
	   		}

			if (sample_type & PERF_SAMPLE_REGS_USER) {
				long long abi;

				memcpy(&abi,&data[offset],sizeof(long long));
				if (!quiet) {
					printf("\tPERF_SAMPLE_REGS_USER, ABI: ");
					if (abi==PERF_SAMPLE_REGS_ABI_NONE) printf ("PERF_SAMPLE_REGS_ABI_NONE");
					if (abi==PERF_SAMPLE_REGS_ABI_32) printf("PERF_SAMPLE_REGS_ABI_32");
					if (abi==PERF_SAMPLE_REGS_ABI_64) printf("PERF_SAMPLE_REGS_ABI_64");
					printf("\n");
				}
				offset+=8;

				offset+=print_regs(quiet,abi,reg_mask,
						&data[offset]);

				if (!quiet) printf("\n");
			}

			if (sample_type & PERF_SAMPLE_REGS_INTR) {
				long long abi;

				memcpy(&abi,&data[offset],sizeof(long long));
				if (!quiet) {
					printf("\tPERF_SAMPLE_REGS_INTR, ABI: ");
					if (abi==PERF_SAMPLE_REGS_ABI_NONE) printf ("PERF_SAMPLE_REGS_ABI_NONE");
					if (abi==PERF_SAMPLE_REGS_ABI_32) printf("PERF_SAMPLE_REGS_ABI_32");
					if (abi==PERF_SAMPLE_REGS_ABI_64) printf("PERF_SAMPLE_REGS_ABI_64");
					printf("\n");
				}
				offset+=8;

				offset+=print_regs(quiet,abi,reg_mask,
						&data[offset]);

				if (!quiet) printf("\n");
			}

			if (sample_type & PERF_SAMPLE_STACK_USER) {
				long long size,dyn_size;
				int *stack_data;
				int k;

				memcpy(&size,&data[offset],sizeof(long long));
				if (!quiet) printf("\tPERF_SAMPLE_STACK_USER, Requested size: %lld\n",size);
				offset+=8;

				stack_data=malloc(size);
				memcpy(stack_data,&data[offset],size);
				offset+=size;

				memcpy(&dyn_size,&data[offset],sizeof(long long));
				if (!quiet) printf("\t\tDynamic (used) size: %lld\n",dyn_size);
				offset+=8;

				if (!quiet) printf("\t\t");
				for(k=0;k<dyn_size;k+=4) {
					if (!quiet) printf("0x%x ",stack_data[k]);
				}

				free(stack_data);

				if (!quiet) printf("\n");
			}

			if (sample_type & PERF_SAMPLE_WEIGHT) {
				long long weight;

				memcpy(&weight,&data[offset],sizeof(long long));
				if (!quiet) printf("\tPERF_SAMPLE_WEIGHT, Weight: %lld ",weight);
				offset+=8;

				if (!quiet) printf("\n");
			}

			if (sample_type & PERF_SAMPLE_DATA_SRC) {
				long long src;

				memcpy(&src,&data[offset],sizeof(long long));
				if (!quiet) printf("\tPERF_SAMPLE_DATA_SRC, Raw: %llx\n",src);
				offset+=8;

				if (!quiet) {
					if (src!=0) printf("\t\t");
					if (src & (PERF_MEM_OP_NA<<PERF_MEM_OP_SHIFT))
						printf("Op Not available ");
					if (src & (PERF_MEM_OP_LOAD<<PERF_MEM_OP_SHIFT))
						printf("Load ");
					if (src & (PERF_MEM_OP_STORE<<PERF_MEM_OP_SHIFT))
						printf("Store ");
					if (src & (PERF_MEM_OP_PFETCH<<PERF_MEM_OP_SHIFT))
						printf("Prefetch ");
					if (src & (PERF_MEM_OP_EXEC<<PERF_MEM_OP_SHIFT))
						printf("Executable code ");

					if (src & (PERF_MEM_LVL_NA<<PERF_MEM_LVL_SHIFT))
						printf("Level Not available ");
					if (src & (PERF_MEM_LVL_HIT<<PERF_MEM_LVL_SHIFT))
						printf("Hit ");
					if (src & (PERF_MEM_LVL_MISS<<PERF_MEM_LVL_SHIFT))
						printf("Miss ");
					if (src & (PERF_MEM_LVL_L1<<PERF_MEM_LVL_SHIFT))
						printf("L1 cache ");
					if (src & (PERF_MEM_LVL_LFB<<PERF_MEM_LVL_SHIFT))
						printf("Line fill buffer ");
					if (src & (PERF_MEM_LVL_L2<<PERF_MEM_LVL_SHIFT))
						printf("L2 cache ");
					if (src & (PERF_MEM_LVL_L3<<PERF_MEM_LVL_SHIFT))
						printf("L3 cache ");
					if (src & (PERF_MEM_LVL_LOC_RAM<<PERF_MEM_LVL_SHIFT))
						printf("Local DRAM ");
					if (src & (PERF_MEM_LVL_REM_RAM1<<PERF_MEM_LVL_SHIFT))
						printf("Remote DRAM 1 hop ");
					if (src & (PERF_MEM_LVL_REM_RAM2<<PERF_MEM_LVL_SHIFT))
						printf("Remote DRAM 2 hops ");
					if (src & (PERF_MEM_LVL_REM_CCE1<<PERF_MEM_LVL_SHIFT))
						printf("Remote cache 1 hop ");
					if (src & (PERF_MEM_LVL_REM_CCE2<<PERF_MEM_LVL_SHIFT))
						printf("Remote cache 2 hops ");
					if (src & (PERF_MEM_LVL_IO<<PERF_MEM_LVL_SHIFT))
						printf("I/O memory ");
					if (src & (PERF_MEM_LVL_UNC<<PERF_MEM_LVL_SHIFT))
						printf("Uncached memory ");

					if (src & (PERF_MEM_SNOOP_NA<<PERF_MEM_SNOOP_SHIFT))
						printf("Not available ");
					if (src & (PERF_MEM_SNOOP_NONE<<PERF_MEM_SNOOP_SHIFT))
						printf("No snoop ");
					if (src & (PERF_MEM_SNOOP_HIT<<PERF_MEM_SNOOP_SHIFT))
						printf("Snoop hit ");
					if (src & (PERF_MEM_SNOOP_MISS<<PERF_MEM_SNOOP_SHIFT))
						printf("Snoop miss ");
					if (src & (PERF_MEM_SNOOP_HITM<<PERF_MEM_SNOOP_SHIFT))
						printf("Snoop hit modified ");

					if (src & (PERF_MEM_LOCK_NA<<PERF_MEM_LOCK_SHIFT))
						printf("Not available ");
					if (src & (PERF_MEM_LOCK_LOCKED<<PERF_MEM_LOCK_SHIFT))
						printf("Locked transaction ");

					if (src & (PERF_MEM_TLB_NA<<PERF_MEM_TLB_SHIFT))
						printf("Not available ");
					if (src & (PERF_MEM_TLB_HIT<<PERF_MEM_TLB_SHIFT))
						printf("Hit ");
					if (src & (PERF_MEM_TLB_MISS<<PERF_MEM_TLB_SHIFT))
						printf("Miss ");
					if (src & (PERF_MEM_TLB_L1<<PERF_MEM_TLB_SHIFT))
						printf("Level 1 TLB ");
					if (src & (PERF_MEM_TLB_L2<<PERF_MEM_TLB_SHIFT))
						printf("Level 2 TLB ");
					if (src & (PERF_MEM_TLB_WK<<PERF_MEM_TLB_SHIFT))
						printf("Hardware walker ");
					if (src & ((long long)PERF_MEM_TLB_OS<<PERF_MEM_TLB_SHIFT))
						printf("OS fault handler ");
				}

				if (!quiet) printf("\n");
			}

			if (sample_type & PERF_SAMPLE_IDENTIFIER) {
				long long abi;

				memcpy(&abi,&data[offset],sizeof(long long));
				if (!quiet) printf("\tPERF_SAMPLE_IDENTIFIER, Raw length: %lld\n",abi);
				offset+=8;

				if (!quiet) printf("\n");
			}

			if (sample_type & PERF_SAMPLE_TRANSACTION) {
				long long abi;

				memcpy(&abi,&data[offset],sizeof(long long));
				if (!quiet) printf("\tPERF_SAMPLE_TRANSACTION, Raw length: %lld\n",abi);
				offset+=8;

				if (!quiet) printf("\n");
			}
			break;

		/* AUX */
		case PERF_RECORD_AUX: {
			long long aux_offset,aux_size,flags;
			long long sample_id;

			memcpy(&aux_offset,&data[offset],sizeof(long long));
			if (!quiet) printf("\tAUX_OFFSET: %lld\n",aux_offset);
			offset+=8;

			memcpy(&aux_size,&data[offset],sizeof(long long));
			if (!quiet) printf("\tAUX_SIZE: %lld\n",aux_size);
			offset+=8;

			memcpy(&flags,&data[offset],sizeof(long long));
			if (!quiet) {
				printf("\tFLAGS: %llx ",flags);
				if (flags & PERF_AUX_FLAG_TRUNCATED) {
					printf("FLAG_TRUNCATED ");
				}
				if (flags & PERF_AUX_FLAG_OVERWRITE) {
					printf("FLAG_OVERWRITE ");
				}
				printf("\n");
			}
			offset+=8;

			memcpy(&sample_id,&data[offset],sizeof(long long));
			if (!quiet) printf("\tSAMPLE_ID: %lld\n",sample_id);
			offset+=8;

			}
			break;

		/* itrace start */
		case PERF_RECORD_ITRACE_START: {
			int pid,tid;

			memcpy(&pid,&data[offset],sizeof(int));
			if (!quiet) printf("\tPID: %d\n",pid);
			offset+=4;

			memcpy(&tid,&data[offset],sizeof(int));
			if (!quiet) printf("\tTID: %d\n",tid);
			offset+=4;
			}
			break;

		/* lost samples PEBS */
		case PERF_RECORD_LOST_SAMPLES: {
			long long lost,sample_id;

			memcpy(&lost,&data[offset],sizeof(long long));
			if (!quiet) printf("\tLOST: %lld\n",lost);
			offset+=8;

			memcpy(&sample_id,&data[offset],sizeof(long long));
			if (!quiet) printf("\tSAMPLE_ID: %lld\n",sample_id);
			offset+=8;
			}
			break;

		/* context switch */
		case PERF_RECORD_SWITCH: {
			long long sample_id;

			memcpy(&sample_id,&data[offset],sizeof(long long));
			if (!quiet) printf("\tSAMPLE_ID: %lld\n",sample_id);
			offset+=8;
			}
			break;

		/* context switch cpu-wide*/
		case PERF_RECORD_SWITCH_CPU_WIDE: {
			int prev_pid,prev_tid;
			long long sample_id;

			memcpy(&prev_pid,&data[offset],sizeof(int));
			if (!quiet) printf("\tPREV_PID: %d\n",prev_pid);
			offset+=4;

			memcpy(&prev_tid,&data[offset],sizeof(int));
			if (!quiet) printf("\tPREV_TID: %d\n",prev_tid);
			offset+=4;

			memcpy(&sample_id,&data[offset],sizeof(long long));
			if (!quiet) printf("\tSAMPLE_ID: %lld\n",sample_id);
			offset+=8;
			}
			break;


		default:
			if (!quiet) printf("\tUnknown type %d\n",event->type);
			/* Probably best to just skip it all */
			offset=size;

		}
		if (events_read) (*events_read)++;
	}

//	mb();
	control_page->data_tail=head;

	free(data);

	return head;

}
