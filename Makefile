all: audit_logger audit_monitor test_audit


audit_logger: audit_logger.c
	gcc -Wall -fPIC -shared -o audit_logger.so audit_logger.c -lcrypto -ldl 


audit_monitor: audit_monitor.c 
	gcc audit_monitor.c -o audit_monitor


test_audit: test_audit.c 
	gcc test_audit.c -o test_audit


run: audit_logger.so test_audit
	LD_PRELOAD=./audit_logger.so ./test_audit


clean:
	rm -rf test_audit
	rm -rf audit_monitor
	rm -rf file_* testfile
	rm -rf protected_*
	

