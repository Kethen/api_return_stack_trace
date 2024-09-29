#ifndef __LOGGING_H
#define __LOGGING_H

#include <pthread.h>
#include <stdio.h>
#include <stdint.h>

extern pthread_mutex_t _log_mutex;
extern int _log_fd;
int init_logging(const char *path);
int write_to_fd(int fd, const uint8_t *buffer, int64_t size);

#define LOG(...){ \
	if(_log_fd >= 0){ \
		pthread_mutex_lock(&_log_mutex); \
		char _log_buf[512]; \
		int _log_len = snprintf(_log_buf, sizeof(_log_buf), __VA_ARGS__); \
		write_to_fd(_log_fd, (uint8_t *)_log_buf, _log_len); \
		pthread_mutex_unlock(&_log_mutex); \
	} \
}

#endif
