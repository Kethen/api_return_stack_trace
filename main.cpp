#include <stdio.h>
#include <stdlib.h>

#include "logging.h"
#include "hooking.h"

__attribute__((constructor))
int init(){
	int ret = init_logging("api_return_stack_trace.log");
	if(ret != 0){
		printf("Failed initializing logging\n");
	}

	ret = hook_apis();
	if(ret != 0){
		LOG("Failed hooking apis, terminating\n");
		exit(1);
	}

	return 0;
}
