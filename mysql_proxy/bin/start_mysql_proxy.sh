#!/bin/bash

C_GREEN="\e[92m"
C_RED="\e[91m"
C_END="\e[0m"

mysql_proxy_dir="{path}/mysql_proxy"

if [ -f "$mysql_proxy_dir/nginx/logs/nginx.pid" ];then
    echo -e "Message: ${C_RED}mysql_proxy is running, please stop it first !${C_END}"
    exit 1
fi

export LD_LIBRARY_PATH=$mysql_proxy_dir/lualib:$mysql_proxy_dir/luajit/lib
$mysql_proxy_dir/nginx/sbin/nginx -p $mysql_proxy_dir/nginx -c $mysql_proxy_dir/nginx/conf/nginx.conf

sleep 1

if [ -f "$mysql_proxy_dir/nginx/logs/nginx.pid" ];then
    echo -e "Message: ${C_GREEN}start mysql_proxy success !${C_END}"
else
    echo -e "Message: ${C_RED}start mysql_proxy failed !${C_END}"
fi
