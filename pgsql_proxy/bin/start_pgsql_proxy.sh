#!/bin/bash

C_GREEN="\e[92m"
C_RED="\e[91m"
C_END="\e[0m"

pgsql_proxy_dir="{path}/pgsql_proxy"

if [ -f "$pgsql_proxy_dir/nginx/logs/nginx.pid" ];then
    echo -e "Message: ${C_RED}pgsql_proxy is running, please stop it first !${C_END}"
    exit 1
fi

export LD_LIBRARY_PATH=$pgsql_proxy_dir/lualib:$pgsql_proxy_dir/luajit/lib
$pgsql_proxy_dir/nginx/sbin/nginx -p $pgsql_proxy_dir/nginx -c $pgsql_proxy_dir/nginx/conf/nginx.conf

sleep 1

if [ -f "$pgsql_proxy_dir/nginx/logs/nginx.pid" ];then
    echo -e "Message: ${C_GREEN}start pgsql_proxy success !${C_END}"
else
    echo -e "Message: ${C_RED}start pgsql_proxy failed !${C_END}"
fi
