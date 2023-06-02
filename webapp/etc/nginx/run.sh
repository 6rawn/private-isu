#!/bin/bash

sed -i -e "s/#tcp/tcp/g" -e "s/#gzip/gzip/g" /etc/nginx/nginx.conf
nginx -g "daemon off;"