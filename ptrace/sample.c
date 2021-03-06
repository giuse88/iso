#include <stdio.h> 
#include <unistd.h> 
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h> 
#define sourceFile 	 "/dev/zero"
#define destFile	 "/dev/null"

#define DEFAULT_BUFFER 	64
#define DEFUALT_ITERATIONS 1024

int main (int argc, char *argv []) {

  int s,d; 
  int size_buffer, loop_iteration;
  char * buf=NULL; 
  int i; 
  
  size_buffer=DEFAULT_BUFFER; 
  loop_iteration=DEFUALT_ITERATIONS;
  
  if ( argc == 2 ) 
    size_buffer=atoi(argv[1]);
  if ( argc == 3 ) {
    size_buffer=atoi(argv[1]);
    loop_iteration=atoi(argv[2]);
  }
  
  puts("Stress test program for write and read system"); 
  
  printf("Number of loops : %d\n", loop_iteration); 
  printf("Buffer size :     %d\n", size_buffer); 
 
  buf=malloc(size_buffer); 
  
  s=open(sourceFile,O_RDONLY); 
  d=open(destFile,O_WRONLY);
  
  
  for ( i=0; i< loop_iteration; i++) {
   read(s, buf, size_buffer); 
   write(d, buf, size_buffer); 
  }
  
  close(s);
  close(d); 
  
  return 0; 

}
