#ifndef THREADPOOL_H
#define THREADPOOL_H

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#else
#include <pthread.h>
#endif

#include <stdint.h>

// Task structure for work queue
typedef struct {
    void (*function)(void *arg);
    void *argument;
} thread_task_t;

// Thread pool structure
typedef struct {
    int num_threads;
    int shutdown;
    int task_count;
    int task_capacity;
    int active_tasks;  // Number of tasks currently being executed
    thread_task_t *tasks;
    int head;
    int tail;

#ifdef _WIN32
    HANDLE *threads;
    CRITICAL_SECTION lock;
    CONDITION_VARIABLE notify;
    CONDITION_VARIABLE work_done;  // Signal when all work is done
#else
    pthread_t *threads;
    pthread_mutex_t lock;
    pthread_cond_t notify;
    pthread_cond_t work_done;
#endif
} threadpool_t;

// Create a thread pool with specified number of threads
threadpool_t* threadpool_create(int num_threads);

// Add a task to the thread pool
int threadpool_add_task(threadpool_t *pool, void (*function)(void *), void *argument);

// Wait for all tasks to complete
void threadpool_wait(threadpool_t *pool);

// Destroy the thread pool
void threadpool_destroy(threadpool_t *pool);

#endif // THREADPOOL_H
