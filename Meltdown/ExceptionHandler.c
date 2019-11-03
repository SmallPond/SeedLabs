#include <stdio.h>
#include <setjmp.h>
#include <signal.h>
static sigjmp_buf jbuf;

static void catch_segv()
{
    siglongjmp(jbuf, 1);
}

int main() 
{
    char *kernel_data_addr = (char *)0xf9967000;
    
	// Register a signal handler
	signal(SIGSEGV, catch_segv);

	if (sigsetjmp(jbuf, 1) == 0) {
	
    	char kernel_data = *kernel_data_addr;
   		// the following statement will not be exec
		printf("Kernel data is : %c.\n", kernel_data);
	} 
	else {
		printf("Memory access violation!\n");
	}
	printf("Program continues to exec.\n");
    return 0;
}
