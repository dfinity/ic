#!/bin/bash
echo "Starting bpftrace..."
bpftrace --unsafe -e '
config = {
    perf_rb_pages=4096;
    log_size=100000000
}
kprobe:chown_common {  
    time("%H:%M:%S: "); 
    printf("PID:%d %s \"%s\" to %d:%d\n", pid, comm, str(((struct path *)arg0)->dentry->d_name.name), arg1, arg2); 
}
kprobe:do_fchownat { 
    time("%H:%M:%S: "); 
    printf("PID:%d %s \"%s\" to %d:%d\n", pid, comm, str(arg1), arg2, arg3); 
}
' -o /tmp/lol.log