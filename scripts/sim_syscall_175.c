#include <unistd.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
  unsigned long syscall_nr = 175;
  char *data = argv[1];
  int i = 0;
  while(data[i] != '\0'){
	++i;
  }
  
  printf("The data is %s, size = %d\n", data, i); 
  syscall(syscall_nr, (void*) data, i, "test=1");
  printf("The data after syscall 175, is %s, size = %d\n", data, i);
}
