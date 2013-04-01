
all:	vdso.s syscall.s  
	gcc -m32 vdso.s -o vdso.out 
	@echo "VDSO compiled for x32 architecture"
	gcc syscall.s -o syscall.out 

clean : 
	rm *.out 

