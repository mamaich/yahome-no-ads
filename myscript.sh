#!/system/bin/sh

mount --bind /data/local/tmp/cacerts/ /system/etc/security/cacerts/

echo "Waiting boot end $(date)" > /data/local/tmp/script.log
chmod 666 /data/local/tmp/script.log
# Wait for boot to complete
until [ "$(getprop sys.boot_completed)" ]
do
 sleep 1
done
echo "Booted at $(date)" >> /data/local/tmp/script.log

iptables -t nat -A OUTPUT -p tcp -d 213.180.193.230 --dport 443 -m owner ! --uid-owner 0 -j REDIRECT --to-ports 8443
iptables -t nat -A OUTPUT -p tcp -d 77.88.21.175 --dport 443 -m owner ! --uid-owner 0 -j REDIRECT --to-ports 8444
/data/local/tmp/tls_proxy &
sleep 1
killall -9 com.yandex.io.sdk
