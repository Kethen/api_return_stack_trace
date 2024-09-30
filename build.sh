set -xe

for arch in x86_64 i686
#for arch in i686
do
	OUT_DIR=dist/${arch}
	rm -rf $OUT_DIR
	mkdir -p $OUT_DIR

	min_hook_lib="MinHook.x86"
	if [ ${arch} == x86_64 ]
	then
		min_hook_lib="MinHook.x64"
	fi
	cp minhook_1.3.3/bin/${min_hook_lib}.dll $OUT_DIR

	asi_loader_path=ultimate_asi_loader/x86/dinput8.dll
	if [ ${arch} == x86_64 ]
	then
		asi_loader_path=ultimate_asi_loader/x64/dinput8.dll
	fi

	CPPC=${arch}-w64-mingw32-g++
	CC=${arch}-w64-mingw32-gcc

	$CPPC -g -fPIC -c logging.cpp -o $OUT_DIR/logging.o
	$CPPC -g -fPIC -c hooking.cpp -o $OUT_DIR/hooking.o -I minhook_1.3.3/include -O0 -std=c++20
	$CPPC -g -fPIC -c main.cpp -o $OUT_DIR/main.o

	$CPPC -g -shared -o $OUT_DIR/api_return_stack_trace.asi $OUT_DIR/logging.o $OUT_DIR/hooking.o $OUT_DIR/main.o -Lminhook_1.3.3/bin -lntdll -lkernel32 -Wl,-Bstatic -lpthread -l${min_hook_lib} -static-libgcc

	rm $OUT_DIR/*.o

	cp $asi_loader_path $OUT_DIR/d3d9.dll
done

