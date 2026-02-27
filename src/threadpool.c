#include "threadpool.h"
#include <stdlib.h>
#include <stdio.h>

#ifdef _WIN32
static unsigned int __stdcall threadpool_worker(void *arg)
#else
static void* threadpool_worker(void *arg)
#endif
{
    threadpool_t *pool = (threadpool_t *)arg;

    printf("DEBUG: Thread pool worker started\n");

    while (1) {
#ifdef _WIN32
        EnterCriticalSection(&pool->lock);

        // Wait for tasks or shutdown
        while (pool->task_count == 0 && !pool->shutdown) {
            printf("DEBUG: Worker waiting for task...\n");
            SleepConditionVariableCS(&pool->notify, &pool->lock, INFINITE);
        }

        if (pool->shutdown) {
            printf("DEBUG: Worker received shutdown signal\n");
            LeaveCriticalSection(&pool->lock);
            break;
        }

        // Get task from queue
        printf("DEBUG: Worker got task from queue\n");
        thread_task_t task = pool->tasks[pool->head];
        pool->head = (pool->head + 1) % pool->task_capacity;
        pool->task_count--;
        pool->active_tasks++;  // Mark task as active

        LeaveCriticalSection(&pool->lock);
#else
        pthread_mutex_lock(&pool->lock);

        while (pool->task_count == 0 && !pool->shutdown) {
            pthread_cond_wait(&pool->notify, &pool->lock);
        }

        if (pool->shutdown) {
            pthread_mutex_unlock(&pool->lock);
            break;
        }

        thread_task_t task = pool->tasks[pool->head];
        pool->head = (pool->head + 1) % pool->task_capacity;
        pool->task_count--;
        pool->active_tasks++;

        pthread_mutex_unlock(&pool->lock);
#endif

        // Execute task
        printf("DEBUG: Worker executing task function...\n");
        (task.function)(task.argument);
        printf("DEBUG: Worker task function completed\n");

        // Mark task as completed
#ifdef _WIN32
        EnterCriticalSection(&pool->lock);
        pool->active_tasks--;
        WakeConditionVariable(&pool->work_done);  // Signal completion
        LeaveCriticalSection(&pool->lock);
#else
        pthread_mutex_lock(&pool->lock);
        pool->active_tasks--;
        pthread_cond_signal(&pool->work_done);
        pthread_mutex_unlock(&pool->lock);
#endif
    }

    printf("DEBUG: Thread pool worker exiting\n");

#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

threadpool_t* threadpool_create(int num_threads) {
    if (num_threads <= 0) {
        num_threads = 1;
    }

    threadpool_t *pool = (threadpool_t *)calloc(1, sizeof(threadpool_t));
    if (pool == NULL) {
        return NULL;
    }

    pool->num_threads = num_threads;
    pool->task_capacity = 256;  // Max queued tasks
    pool->active_tasks = 0;     // Initialize active task counter
    pool->tasks = (thread_task_t *)calloc(pool->task_capacity, sizeof(thread_task_t));

    if (pool->tasks == NULL) {
        free(pool);
        return NULL;
    }

#ifdef _WIN32
    pool->threads = (HANDLE *)calloc(num_threads, sizeof(HANDLE));
    if (pool->threads == NULL) {
        free(pool->tasks);
        free(pool);
        return NULL;
    }

    InitializeCriticalSection(&pool->lock);
    InitializeConditionVariable(&pool->notify);
    InitializeConditionVariable(&pool->work_done);  // Initialize work_done condition

    // Create worker threads
    for (int i = 0; i < num_threads; i++) {
        pool->threads[i] = (HANDLE)_beginthreadex(NULL, 0, threadpool_worker, pool, 0, NULL);
        if (pool->threads[i] == NULL) {
            threadpool_destroy(pool);
            return NULL;
        }
    }
#else
    pool->threads = (pthread_t *)calloc(num_threads, sizeof(pthread_t));
    if (pool->threads == NULL) {
        free(pool->tasks);
        free(pool);
        return NULL;
    }

    pthread_mutex_init(&pool->lock, NULL);
    pthread_cond_init(&pool->notify, NULL);
    pthread_cond_init(&pool->work_done, NULL);

    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&pool->threads[i], NULL, threadpool_worker, pool) != 0) {
            threadpool_destroy(pool);
            return NULL;
        }
    }
#endif

    return pool;
}

int threadpool_add_task(threadpool_t *pool, void (*function)(void *), void *argument) {
    if (pool == NULL || function == NULL) {
        return -1;
    }
    
#ifdef _WIN32
    EnterCriticalSection(&pool->lock);
    
    // Check if queue is full
    if (pool->task_count >= pool->task_capacity) {
        LeaveCriticalSection(&pool->lock);
        return -1;
    }
    
    // Add task to queue
    pool->tasks[pool->tail].function = function;
    pool->tasks[pool->tail].argument = argument;
    pool->tail = (pool->tail + 1) % pool->task_capacity;
    pool->task_count++;
    
    // Wake up a worker thread
    WakeConditionVariable(&pool->notify);
    
    LeaveCriticalSection(&pool->lock);
#else
    pthread_mutex_lock(&pool->lock);
    
    if (pool->task_count >= pool->task_capacity) {
        pthread_mutex_unlock(&pool->lock);
        return -1;
    }
    
    pool->tasks[pool->tail].function = function;
    pool->tasks[pool->tail].argument = argument;
    pool->tail = (pool->tail + 1) % pool->task_capacity;
    pool->task_count++;
    
    pthread_cond_signal(&pool->notify);
    
    pthread_mutex_unlock(&pool->lock);
#endif
    
    return 0;
}

void threadpool_wait(threadpool_t *pool) {
    if (pool == NULL) {
        return;
    }

    printf("DEBUG: threadpool_wait() - Waiting for all tasks to complete...\n");

    // Wait until all tasks are completed (both queued and active)
#ifdef _WIN32
    EnterCriticalSection(&pool->lock);
    while (pool->task_count > 0 || pool->active_tasks > 0) {
        printf("DEBUG: threadpool_wait() - task_count=%d, active_tasks=%d\n", 
               pool->task_count, pool->active_tasks);
        SleepConditionVariableCS(&pool->work_done, &pool->lock, INFINITE);
    }
    LeaveCriticalSection(&pool->lock);
#else
    pthread_mutex_lock(&pool->lock);
    while (pool->task_count > 0 || pool->active_tasks > 0) {
        pthread_cond_wait(&pool->work_done, &pool->lock);
    }
    pthread_mutex_unlock(&pool->lock);
#endif

    printf("DEBUG: threadpool_wait() - All tasks completed!\n");
}

void threadpool_destroy(threadpool_t *pool) {
    if (pool == NULL) {
        return;
    }
    
#ifdef _WIN32
    EnterCriticalSection(&pool->lock);
    pool->shutdown = 1;
    WakeAllConditionVariable(&pool->notify);
    LeaveCriticalSection(&pool->lock);
    
    // Wait for all threads to finish
    if (pool->threads) {
        WaitForMultipleObjects(pool->num_threads, pool->threads, TRUE, INFINITE);
        for (int i = 0; i < pool->num_threads; i++) {
            CloseHandle(pool->threads[i]);
        }
        free(pool->threads);
    }
    
    DeleteCriticalSection(&pool->lock);
#else
    pthread_mutex_lock(&pool->lock);
    pool->shutdown = 1;
    pthread_cond_broadcast(&pool->notify);
    pthread_mutex_unlock(&pool->lock);
    
    if (pool->threads) {
        for (int i = 0; i < pool->num_threads; i++) {
            pthread_join(pool->threads[i], NULL);
        }
        free(pool->threads);
    }
    
    pthread_mutex_destroy(&pool->lock);
    pthread_cond_destroy(&pool->notify);
#endif
    
    if (pool->tasks) {
        free(pool->tasks);
    }
    
    free(pool);
}
