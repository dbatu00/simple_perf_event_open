#include <pthread.h>
#include <stdio.h>

void* thread_func(void* args) {
    pthread_barrier_t *barrier = (pthread_barrier_t *)args;
    printf("waiting for barrier 1\n");
    pthread_barrier_wait(barrier);
    printf("waiting for barrier 2\n");
    pthread_barrier_wait(barrier);
    printf("passed barrier\n");

    return NULL;
}

int main() {
    int const num_threads = 5;
    pthread_t threads[num_threads];
    pthread_barrier_t actual_barrier;
    //pthread_barrier_t *barrier = &actual_barrier;

    pthread_barrier_init(&actual_barrier, NULL, num_threads);

    int i;
    for (i = 0; i < num_threads; i++) {
        pthread_create(&threads[i], NULL, thread_func, (void*)&actual_barrier);
    }

    for (i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}
