#include <stdio.h> 
#include <unistd.h> 
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


int main () {

   int fd; 
  char fileName[100]="/etc/passwd";

  printf ("The address of the path name is 0x%X \n", (unsigned)fileName); 
  
  fd=open(fileName,O_RDONLY); 
  close(fd); 

  printf("The file name is %s\n" , fileName); 
  
  return 0; 

}
