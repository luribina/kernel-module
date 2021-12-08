obj-m += lab2.o

all: make_user make_module

make_user:
	g++ -o user user.cpp

make_module: 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm user
