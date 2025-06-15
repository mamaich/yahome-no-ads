#!/system/bin/sh
echo "Script started at $(date)" > /data/local/tmp/script.log
chmod 666 /data/local/tmp/script.log

if [ ! -f /system/etc/security/cacerts/c8750f0d.0 ]; then
echo "File /system/etc/security/cacerts/c8750f0d.0 does not exist, remounting / RW" >> /data/local/tmp/script.log
mount -o remount,rw /
echo -----BEGIN CERTIFICATE----- > /system/etc/security/cacerts/c8750f0d.0
echo MIIDoTCCAomgAwIBAgIGDxy0SqPyMA0GCSqGSIb3DQEBCwUAMCgxEjAQBgNVBAMM >> /system/etc/security/cacerts/c8750f0d.0
echo CW1pdG1wcm94eTESMBAGA1UECgwJbWl0bXByb3h5MB4XDTIyMDgyNTEwMjM0OVoX >> /system/etc/security/cacerts/c8750f0d.0
echo DTI1MDgyNjEwMjM0OVowKDESMBAGA1UEAwwJbWl0bXByb3h5MRIwEAYDVQQKDAlt >> /system/etc/security/cacerts/c8750f0d.0
echo aXRtcHJveHkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC3Row23ZJt >> /system/etc/security/cacerts/c8750f0d.0
echo PzcIFM6rjt2XNQMu+JrZOdYZB0GdRna0khwRpsYHPJ/KGMKWQlIR5QMYarHcpmx1 >> /system/etc/security/cacerts/c8750f0d.0
echo MQTed02d8LlHCRyO+5KiCegiwtrmOEn/I9oSGYc8Is2bnTwesd3B4DfwjUK8DLdN >> /system/etc/security/cacerts/c8750f0d.0
echo Y6RVLea0hLH538nwu2ukY4qY61Yn0LXvplaeGcTWOuNKGgiOF53hyn+xq9sjymdy >> /system/etc/security/cacerts/c8750f0d.0
echo ik4x0bZXiXRrlauLvia1de0gnNSOXzsD1t7AHAc+yZwFPlp313Nu8ALIt9ewCfdF >> /system/etc/security/cacerts/c8750f0d.0
echo FPqksPxSabpuIdbvME5GkZEelrHIPzt1T2VQqjm9OAZG2DBJFtF3YzsueQBdspKe >> /system/etc/security/cacerts/c8750f0d.0
echo p7t6iq3tuyQdAgMBAAGjgdAwgc0wDwYDVR0TAQH/BAUwAwEB/zARBglghkgBhvhC >> /system/etc/security/cacerts/c8750f0d.0
echo AQEEBAMCAgQweAYDVR0lBHEwbwYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcD >> /system/etc/security/cacerts/c8750f0d.0
echo BAYIKwYBBQUHAwgGCisGAQQBgjcCARUGCisGAQQBgjcCARYGCisGAQQBgjcKAwEG >> /system/etc/security/cacerts/c8750f0d.0
echo CisGAQQBgjcKAwMGCisGAQQBgjcKAwQGCWCGSAGG+EIEATAOBgNVHQ8BAf8EBAMC >> /system/etc/security/cacerts/c8750f0d.0
echo AQYwHQYDVR0OBBYEFPpjzQxrSpiRSkgKG5Zd5ayHvl5EMA0GCSqGSIb3DQEBCwUA >> /system/etc/security/cacerts/c8750f0d.0
echo A4IBAQCcKlGlyvtiKcm66yNKiFn5DDV2zNA0IoI84UB9LLXG0F+JTSYJMrCfsaR/ >> /system/etc/security/cacerts/c8750f0d.0
echo s3DXeOb7ofpB4p5v3/+m8OjhYdtLMdlOmW4LTY+HjTRnJju0Getq3PcOiz+Djf4d >> /system/etc/security/cacerts/c8750f0d.0
echo 0As4WEQ+KEwl3Wl5n4bmCvULhRG7tqZD5vcRq7IUXrhtaUPlsi0FrdUklYlxZKtn >> /system/etc/security/cacerts/c8750f0d.0
echo IfXoPdvULbWDcFUt7DvAxZRC3XsFUbmEXtBR+ntDHBL9K3Byi6kJ+Mvrviqc6Qpu >> /system/etc/security/cacerts/c8750f0d.0
echo lMJisuOTJJEmvMmW6ITnkz+aDl6uDxXP0l9VogGrLISyHv95i9+ata7GYCoKdkQ2 >> /system/etc/security/cacerts/c8750f0d.0
echo nLu1XmZx9TdHOSxge4RkSjv1MzKN >> /system/etc/security/cacerts/c8750f0d.0
echo -----END CERTIFICATE----- >> /system/etc/security/cacerts/c8750f0d.0
chmod 666 /system/etc/security/cacerts/c8750f0d.0
sync
mount -o remount,ro /
fi

# Wait for boot to complete
until [ "$(getprop sys.boot_completed)" ]
do
 sleep 1
done
echo "Booted at $(date)" >> /data/local/tmp/script.log

iptables -t nat -A OUTPUT -p tcp -d 213.180.193.230 --dport 443 -m owner ! --uid-owner 0 -j REDIRECT --to-ports 8443
iptables -t nat -A OUTPUT -p tcp -d 77.88.21.175 --dport 443 -m owner ! --uid-owner 0 -j REDIRECT --to-ports 8444
chmod +x /data/local/tmp/tls_proxy &>> /data/local/tmp/script.log
/data/local/tmp/tls_proxy &
sleep 1
killall -9 com.yandex.io.sdk
