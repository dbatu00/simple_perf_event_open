#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) 
{
    if (argc > 1) 
    {
        pid_t profiled_pid = atoi(argv[1]);
        printf("Received process ID: %d\n", profiled_pid);
        int status;
        waitpid(profiled_pid, &status, 0);
        if (WIFEXITED(status)) {
            printf("Profiled program finished with status: %d\n", WEXITSTATUS(status));
        }
    } else {
        fprintf(stderr, "Error: No process ID passed\n");
    }
    return 0;
}

