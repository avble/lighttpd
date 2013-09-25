#!/bin/sh 
rm -rf /var/www/html/output/*

lighttpd -D -f lighttpd.conf
