BOFNAME := patchwerk
CC_x64 := x86_64-w64-mingw32-gcc

all: 
	x86_64-w64-mingw32-gcc $(BOFNAME).c -c -o $(BOFNAME).x64.o -masm=intel
clean:
	rm $(BOFNAME).x64.o
