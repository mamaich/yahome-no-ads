#!/system/bin/sh

echo "Script started at $(date)" > /data/local/tmp/script.log
chmod 666 /data/local/tmp/script.log

mount -o loop /data/local/tmp/myfs.ext4 /vendor/xbin &>> /data/local/tmp/script.log
/vendor/xbin/sepolicy-inject -Z kernel -l &>> /data/local/tmp/script.log

/system/bin/fw_setenv upgrade_step 3 &>> /data/local/tmp/script.log
/system/bin/fw_setenv silent 0 &>> /data/local/tmp/script.log
/system/bin/fw_setenv EnableSelinux permissive &>> /data/local/tmp/script.log
/system/bin/fw_setenv setenv otg_device 0 &>> /data/local/tmp/script.log

mkdir /data/local/tmp/cacerts/
cp /system/etc/security/cacerts/* /data/local/tmp/cacerts/
echo -----BEGIN CERTIFICATE----- > /data/local/tmp/cacerts/c8750f0d.0
echo MIIDoTCCAomgAwIBAgIGDxy0SqPyMA0GCSqGSIb3DQEBCwUAMCgxEjAQBgNVBAMM >> /data/local/tmp/cacerts/c8750f0d.0
echo CW1pdG1wcm94eTESMBAGA1UECgwJbWl0bXByb3h5MB4XDTIyMDgyNTEwMjM0OVoX >> /data/local/tmp/cacerts/c8750f0d.0
echo DTI1MDgyNjEwMjM0OVowKDESMBAGA1UEAwwJbWl0bXByb3h5MRIwEAYDVQQKDAlt >> /data/local/tmp/cacerts/c8750f0d.0
echo aXRtcHJveHkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC3Row23ZJt >> /data/local/tmp/cacerts/c8750f0d.0
echo PzcIFM6rjt2XNQMu+JrZOdYZB0GdRna0khwRpsYHPJ/KGMKWQlIR5QMYarHcpmx1 >> /data/local/tmp/cacerts/c8750f0d.0
echo MQTed02d8LlHCRyO+5KiCegiwtrmOEn/I9oSGYc8Is2bnTwesd3B4DfwjUK8DLdN >> /data/local/tmp/cacerts/c8750f0d.0
echo Y6RVLea0hLH538nwu2ukY4qY61Yn0LXvplaeGcTWOuNKGgiOF53hyn+xq9sjymdy >> /data/local/tmp/cacerts/c8750f0d.0
echo ik4x0bZXiXRrlauLvia1de0gnNSOXzsD1t7AHAc+yZwFPlp313Nu8ALIt9ewCfdF >> /data/local/tmp/cacerts/c8750f0d.0
echo FPqksPxSabpuIdbvME5GkZEelrHIPzt1T2VQqjm9OAZG2DBJFtF3YzsueQBdspKe >> /data/local/tmp/cacerts/c8750f0d.0
echo p7t6iq3tuyQdAgMBAAGjgdAwgc0wDwYDVR0TAQH/BAUwAwEB/zARBglghkgBhvhC >> /data/local/tmp/cacerts/c8750f0d.0
echo AQEEBAMCAgQweAYDVR0lBHEwbwYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcD >> /data/local/tmp/cacerts/c8750f0d.0
echo BAYIKwYBBQUHAwgGCisGAQQBgjcCARUGCisGAQQBgjcCARYGCisGAQQBgjcKAwEG >> /data/local/tmp/cacerts/c8750f0d.0
echo CisGAQQBgjcKAwMGCisGAQQBgjcKAwQGCWCGSAGG+EIEATAOBgNVHQ8BAf8EBAMC >> /data/local/tmp/cacerts/c8750f0d.0
echo AQYwHQYDVR0OBBYEFPpjzQxrSpiRSkgKG5Zd5ayHvl5EMA0GCSqGSIb3DQEBCwUA >> /data/local/tmp/cacerts/c8750f0d.0
echo A4IBAQCcKlGlyvtiKcm66yNKiFn5DDV2zNA0IoI84UB9LLXG0F+JTSYJMrCfsaR/ >> /data/local/tmp/cacerts/c8750f0d.0
echo s3DXeOb7ofpB4p5v3/+m8OjhYdtLMdlOmW4LTY+HjTRnJju0Getq3PcOiz+Djf4d >> /data/local/tmp/cacerts/c8750f0d.0
echo 0As4WEQ+KEwl3Wl5n4bmCvULhRG7tqZD5vcRq7IUXrhtaUPlsi0FrdUklYlxZKtn >> /data/local/tmp/cacerts/c8750f0d.0
echo IfXoPdvULbWDcFUt7DvAxZRC3XsFUbmEXtBR+ntDHBL9K3Byi6kJ+Mvrviqc6Qpu >> /data/local/tmp/cacerts/c8750f0d.0
echo lMJisuOTJJEmvMmW6ITnkz+aDl6uDxXP0l9VogGrLISyHv95i9+ata7GYCoKdkQ2 >> /data/local/tmp/cacerts/c8750f0d.0
echo nLu1XmZx9TdHOSxge4RkSjv1MzKN >> /data/local/tmp/cacerts/c8750f0d.0
echo -----END CERTIFICATE----- >> /data/local/tmp/cacerts/c8750f0d.0
chmod 666 /data/local/tmp/cacerts/c8750f0d.0
mount --bind /data/local/tmp/cacerts/ /system/etc/security/cacerts/

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
#wait 2 min so wifi is certainly connected, then restart io sdk to reload config caches
(sleep 120; killall -9 com.yandex.io.sdk) &
