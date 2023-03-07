#!/bin/sh
# include locations to returns 403 for heartbeats
mount --bind /etc/nginx/conf.d/hb-pause.locations /etc/nginx/conf.d/hb.locations

#reload nginx to pause HB this will cause the load balancer to failover,
#while we continue serving the last remaining requests for next 30 seconds
/bin/kill -s HUP $(/bin/cat /var/run/nginx.pid)
sleep 30

#Kill nginx
/bin/kill -s TERM $(/bin/cat /var/run/nginx.pid)

# Restore the hb location for the next nginx startup
while umount /etc/nginx/conf.d/hb.locations; do
    echo "Unmounting hb.location"
done
