#ifndef _DXYH_THREAD_H
#define _DXYH_THREAD_H

#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>

void Pthread_create(pthread_t *tid, const pthread_attr_t *attr,
		void *(*func)(void *), void *arg);
void Pthread_join(pthread_t tid, void **status);
void Pthread_detach(pthread_t tid);
void Pthread_kill(pthread_t tid, int signo);
void Pthread_mutexattr_init(pthread_mutexattr_t *attr);
void Pthread_mutex_init(pthread_mutex_t *mptr,
		pthread_mutexattr_t *attr);
void Pthread_mutex_lock(pthread_mutex_t *mptr);
void Pthread_mutex_unlock(pthread_mutex_t *mptr);
void Pthread_mutex_destroy(pthread_mutex_t *mptr);
void Pthread_mutexattr_setpshared(pthread_mutexattr_t *attr,
		int flag);
void Pthread_once(pthread_once_t *ptr, void (*func)(void));
void Pthread_key_create(pthread_key_t *key, void (*func)(void *));
void Pthread_setspecific(pthread_key_t key, const void *value);
ssize_t Readline_r(int fd, void *vptr, size_t maxlen);
void my_lock_mutex_init(void);
void my_lock_mutex_wait(void);
void my_lock_mutex_release(void);
void Sem_init(sem_t *sem, int pshared, unsigned value);
void Sem_trywait(sem_t *sem);
void Sem_wait(sem_t *sem);
void Sem_post(sem_t *sem);
void Sem_destroy(sem_t *sem);
#endif

