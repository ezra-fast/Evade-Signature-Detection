#include <stdio.h>
#include <sys/mman.h>
#include <string.h>

int main(int argc, char **argv) {

	char * buffer = "";

	for (int i = 0; i < strlen(buffer); i++) {
		printf("%x", buffer[i]);
	}
	return 0;

	void * functionPointer = mmap(0, strlen(buffer), PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, -1, 0);	// Give me the memory for the shellcode

	memcpy(functionPointer, buffer, strlen(buffer));			// Here, here is the shellcode

	((void (*)())functionPointer)();				// execute the shellcode by calling the code buffer() points to

	return 0;
}

