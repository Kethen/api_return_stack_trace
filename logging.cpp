#include <pthread.h>
#include <fcntl.h>
#include <stdint.h>

pthread_mutex_t _log_mutex;
int _log_fd = -1;

int init_logging(const char *path){
	if(pthread_mutex_init(&_log_mutex, NULL) != 0){
		return -1;
	}

	_log_fd = open(path, O_WRONLY | O_TRUNC | O_BINARY | O_CREAT, 00644);
	if(_log_fd < 0){
		return -1;
	}

	return 0;
}

int write_to_fd(int fd, const uint8_t *buffer, int64_t size){
	int64_t bytes_written = 0;
	while(bytes_written != size){
		int64_t ret = write(fd, &buffer[bytes_written], size - bytes_written);
		if(ret < 0){
			return ret;
		}
		bytes_written += ret;
	}
	return bytes_written;
}
