#include <windows.h>
#include <fileapi.h>
#include <winbase.h>
#include <memoryapi.h>

#include <MinHook.h>

#include "logging.h"
#include "hooking.h"

#include <list>
#include <string>

// limit stack trace if needed, it seems that gcc's built in can't detect frame top correctly on vc built binaries
static std::list<HANDLE> read_map_white_list;

static void push_read_map_white_list(HANDLE handle){
	read_map_white_list.push_front(handle);
	if(read_map_white_list.size() > 100){
		read_map_white_list.pop_back();
	}
}

static bool in_read_map_white_list(HANDLE handle){
	auto item = read_map_white_list.begin();
	while(item != read_map_white_list.end()){
		if(*item == handle){
			return true;
		}
		item++;
	}
	return false;
}

// add hooks here

typedef HANDLE (WINAPI *CREATE_FILE_A) (LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE (WINAPI *CREATE_FILE_W) (LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

CREATE_FILE_A CreateFileA_orig;
HANDLE WINAPI CreateFileA_patched (LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile){
	HANDLE ret = CreateFileA_orig(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
	LOG("%s, lpFileName %s, dwDesiredAccess 0x%08x, dwShareMode 0x%08x, lpSecurityAttributes 0x%016x, dwCreationDisposition 0x%08x, dwFlagsAndAttributes 0x%08x, hTemplateFile 0x%016x, ret 0x%016x\n", __func__, lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, ret);
	DUMP_RET_STACK(5);

	if(ret != INVALID_HANDLE_VALUE){
		push_read_map_white_list(ret);
	}
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

	if(ret != INVALID_HANDLE_VALUE){
		//push_read_map_white_list(ret);
	}
	return ret;
}

typedef WINBOOL (WINAPI *READ_FILE) (HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);

READ_FILE ReadFile_orig;

WINBOOL WINAPI ReadFile_patched (HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped){
	WINBOOL ret = ReadFile_orig(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
	wchar_t path_buf_w[512] = {0};
	char path_buf[1024] = {0};
	GetFinalPathNameByHandleW(hFile, path_buf_w, sizeof(path_buf_w), 0);
	wcstombs(path_buf, path_buf_w, sizeof(path_buf));
	path_buf[sizeof(path_buf) - 1] = '\0';
	LOG("%s, path %s, hFile 0x%016x, lpBuffer 0x%016x, nNumberOfBytesToRead 0x%08x, lpNumberOfBytesRead 0x%016x, lpOverlapped 0x%016x, ret %s\n", __func__, path_buf, hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped, ret? "true": "false");
	if(in_read_map_white_list(hFile)){
		push_read_map_white_list(hFile);
		DUMP_RET_STACK(5);
	}else{
		DUMP_RET_STACK(0);
	}
	return ret;
}

typedef HANDLE (WINAPI *CREATE_FILE_MAPPING_A) (HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName);

CREATE_FILE_MAPPING_A CreateFileMappingA_orig;
HANDLE WINAPI CreateFileMappingA_patched (HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName){
	HANDLE ret = CreateFileMappingA_orig(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
	wchar_t path_buf_w[512] = {0};
	char path_buf[1024] = {0};
	GetFinalPathNameByHandleW(hFile, path_buf_w, sizeof(path_buf_w), 0);
	wcstombs(path_buf, path_buf_w, sizeof(path_buf));
	path_buf[sizeof(path_buf) - 1] = '\0';
	LOG("%s, path %s, lpName 0x%016x, lpFileMappingAttributes 0x%016x, flProtect 0x%08x, dwMaximumSizeHigh 0x%08x, 0x%08x dwMaximumSizeLow, lpName %s, ret 0x%016x\n", path_buf, hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName, ret);

	if(in_read_map_white_list(hFile)){
		push_read_map_white_list(hFile);
		DUMP_RET_STACK(5);
	}else{
		DUMP_RET_STACK(0);
	}
	return ret;
}

typedef HANDLE (WINAPI *CREATE_FILE_MAPPING_W) (HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName);

CREATE_FILE_MAPPING_W CreateFileMappingW_orig;
HANDLE WINAPI CreateFileMappingW_patched (HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName){
	HANDLE ret = CreateFileMappingW_orig(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
	wchar_t path_buf_w[512] = {0};
	char path_buf[1024] = {0};
	GetFinalPathNameByHandleW(hFile, path_buf_w, sizeof(path_buf_w), 0);
	wcstombs(path_buf, path_buf_w, sizeof(path_buf));
	path_buf[sizeof(path_buf) - 1] = '\0';

	int len = wcstombs(NULL, lpName, 0);
	char *name_buf = (char *)malloc(len + 1);
	if(name_buf != NULL){
		memset(name_buf, 0, len + 1);
		wcstombs(name_buf, lpName, len + 1);
		LOG("%s, path %s, hFile 0x%016x, lpFileMappingAttributes 0x%016x, flProtect 0x%08x, dwMaximumSizeHigh 0x%08x, 0x%08x dwMaximumSizeLow, lpName %s, ret 0x%016x\n", __func__, path_buf, hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, name_buf, ret);
		free(name_buf);
	}

	if(in_read_map_white_list(hFile)){
		push_read_map_white_list(hFile);
		DUMP_RET_STACK(5);
	}else{
		DUMP_RET_STACK(0);
	}
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

	ret = MH_CreateHook((void *)&ReadFile, (void *)&ReadFile_patched, (void **)&ReadFile_orig);
	if(ret != MH_OK){
		LOG("Failed hooking ReadFile\n");
		return -1;
	}
	ret = MH_EnableHook((void *)&ReadFile);
	if(ret != MH_OK){
		LOG("Failed enabling ReadFile hook\n");
		return -1;
	}

	ret = MH_CreateHook((void *)&CreateFileMappingA, (void *)&CreateFileMappingA_patched, (void **)&CreateFileMappingA_orig);
	if(ret != MH_OK){
		LOG("Failed hooking CreateFileMappingA\n");
		return -1;
	}
	ret = MH_EnableHook((void *)&CreateFileMappingA);
	if(ret != MH_OK){
		LOG("Failed enabling CreateFileMappingA hook\n");
		return -1;
	}

	ret = MH_CreateHook((void *)&CreateFileMappingW, (void *)&CreateFileMappingW_patched, (void **)&CreateFileMappingW_orig);
	if(ret != MH_OK){
		LOG("Failed hooking CreateFileMappingW\n");
		return -1;
	}
	ret = MH_EnableHook((void *)&CreateFileMappingW);
	if(ret != MH_OK){
		LOG("Failed enabling CreateFileMappingW hook\n");
		return -1;
	}

	return 0;
}
