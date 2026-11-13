#!/bin/sh
/usr/sbin/sshd -o PasswordAuthentication=no
exec nginx -g 'daemon off;'
