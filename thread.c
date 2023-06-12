#include <stdio.h>
#include <pthread.h>

#define NUM_THREADS 8
#define MAX_COUNT 1000000

pthread_mutex_t mutex;

void* incrementCounter(void* threadid) {
    int* counter = (int*)threadid;
    for (int i = 0; i < MAX_COUNT; i++) {
        pthread_mutex_lock(&mutex);
        (*counter)++;
        pthread_mutex_unlock(&mutex);
    }
    pthread_exit(NULL);
}

int main() {
    pthread_t threads[NUM_THREADS];
    int counters[NUM_THREADS];
    pthread_mutex_init(&mutex, NULL);

    for (int i = 0; i < NUM_THREADS; i++) {
        printf("Creating thread %d with counter at address %p\n", i, &counters[i]);
        counters[i] = 0;
        pthread_create(&threads[i], NULL, incrementCounter, (void*)&counters[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        printf("Thread %d counter: %d\n", i, counters[i]);
    }
    pthread_mutex_destroy(&mutex);
    return 0;
}

