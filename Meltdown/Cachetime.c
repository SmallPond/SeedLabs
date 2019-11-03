#include <stdio.h>
#include <emmintrin.h>
#include <stdint.h>
#include <x86intrin.h>


uint8_t array[10*4096];

int main(int argc, const char **argv) {
    int junk = 0;
    register uint64_t time1, time2;
    volatile uint8_t *addr;
    int i;
    for(i=0; i<10; i++) array[i*4096] = 1;

    // FLush
    for(i=0; i<10; i++) _mm_clflush(&array[i*4096]);
    
    // Access
    array[3*4096] = 100;
    array[7*4096] = 200;

    for(i=0; i<10; i++) {
    	addr = &array[i*4096];
	// timestamp
	time1 = __rdtscp(&junk);
	junk = *addr;
	time2 = __rdtscp(&junk) - time1;
	printf("Access time for array[%d*4096]: %d CPU cycles\n",i, (int)time2);
    }
    return 0;
}
