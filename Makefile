obj=testpcap.o
testpcap:$(obj)
	gcc -o testpcap testpcap.c -lpcap
.PHONY:clean
clean:
	re $(obj)
