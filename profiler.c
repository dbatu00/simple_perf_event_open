#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

int main(int argc, char* argv[]) {
    if (argc > 1) {
        int pid = atoi(argv[1]);
        pid_t child_pid = fork();
        if (child_pid == 0) {
            printf("Process ID: %d\n", pid);
            // code that does the profiling
        } else {
            wait(NULL);
            printf("Profiling done.\n");
        }
    } else {
        fprintf(stderr, "Error: No process ID passed\n");
    }
    return 0;
}


