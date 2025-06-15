#!/system/bin/sh
echo Remounting / RW
mount -o remount,rw /
echo Appending init.rc
echo "" >>/init.rc
echo "service tls_proxy /system/bin/sh /data/local/tmp/myscript-9.sh" >>/init.rc
echo "    class main" >>/init.rc
echo "    oneshot" >>/init.rc
echo "    seclabel u:r:shell:s0" >>/init.rc
echo Remounting / RO
mount -o remount,ro /
