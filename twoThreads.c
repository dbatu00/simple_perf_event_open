#include <stdio.h>
#include <pthread.h>

// Function executed by the threads
void* threadFunction(void* arg) {
    int threadArg = *(int*)arg;
    //printf("Thread argument: %d\n", threadArg);
    printf("Thread ID:% lu | monitored CPU: %d\n", pthread_self(), threadArg);
    // Perform thread-specific operations
    // ...
 

    return NULL;
}

int main() {
    pthread_t thread1, thread2;
    int arg1 = 10;
    int arg2 = 20;

    // Create thread 1
    if (pthread_create(&thread1, NULL, threadFunction, &arg1) != 0) {
        printf("Failed to create thread 1\n");
        return 1;
    }

    // Create thread 2
    if (pthread_create(&thread2, NULL, threadFunction, &arg2) != 0) {
        printf("Failed to create thread 2\n");
        return 1;
    }

    // Wait for thread 1 to finish
    if (pthread_join(thread1, NULL) != 0) {
        printf("Failed to join thread 1\n");
        return 1;
    }

    // Wait for thread 2 to finish
    if (pthread_join(thread2, NULL) != 0) {
        printf("Failed to join thread 2\n");
        return 1;
    }

    printf("Threads completed\n");
    return 0;
}
