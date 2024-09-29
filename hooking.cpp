#include <windows.h>
#include <fileapi.h>

#include <MinHook.h>

#include "logging.h"
#include "hooking.h"

// add hooks here

typedef HANDLE (WINAPI *CREATE_FILE_A) (LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE (WINAPI *CREATE_FILE_W) (LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

CREATE_FILE_A CreateFileA_orig;
HANDLE WINAPI CreateFileA_patched (LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile){
	HANDLE ret = CreateFileA_orig(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	LOG("%s, lpFileName %s, dwDesiredAccess 0x%08x, dwShareMode 0x%08x, lpSecurityAttributes 0x%016x, dwCreationDisposition 0x%08x, dwFlagsAndAttributes 0x%08x, hTemplateFile 0x%016x, ret 0x%016x\n", __func__, lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, ret);
	DUMP_RET_STACK(5);
	return ret;
}

CREATE_FILE_W CreateFileW_orig;
HANDLE WINAPI CreateFileW_patched (LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile){
	HANDLE ret = CreateFileW_orig(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	size_t len = wcstombs(NULL, lpFileName, 0);
	char *path_buf = (char *)malloc(len + 1);
	if(path_buf != NULL){
		memset(path_buf, 0, len + 1);
		wcstombs(path_buf, lpFileName, len + 1);
		LOG("%s, lpFileName %s, dwDesiredAccess 0x%08x, dwShareMode 0x%08x, lpSecurityAttributes 0x%016x, dwCreationDisposition 0x%08x, dwFlagsAndAttributes 0x%08x, hTemplateFile 0x%016x, ret 0x%016x\n", __func__, path_buf, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, ret);
		free(path_buf);
	}
	DUMP_RET_STACK(5);
	return ret;
}

int hook_apis(){
	int ret = MH_Initialize();
	if(ret != MH_OK && ret != MH_ERROR_ALREADY_INITIALIZED){
		LOG("Failed initializing MinHook, %d\n", ret);
		return -1;
	}

	ret = MH_CreateHook((void *)&CreateFileA, (void *)&CreateFileA_patched, (void **)&CreateFileA_orig);
	if(ret != MH_OK){
		LOG("Failed hooking CreateFileA\n");
		return -1;
	}
	ret = MH_EnableHook((void *)&CreateFileA);
	if(ret != MH_OK){
		LOG("Failed enabling CreateFileA hook\n");
		return -1;
	}

	ret = MH_CreateHook((void *)&CreateFileW, (void *)&CreateFileW_patched, (void **)&CreateFileW_orig);
	if(ret != MH_OK){
		LOG("Failed hooking CreateFileW\n");
		return -1;
	}
	ret = MH_EnableHook((void *)&CreateFileW);
	if(ret != MH_OK){
		LOG("Failed enabling CreateFileW hook\n");
		return -1;
	}

	return 0;
}
