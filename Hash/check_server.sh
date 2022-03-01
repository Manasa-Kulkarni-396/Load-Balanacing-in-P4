#!/bin/bash
CLI_PATH=/home/vagrant/behavioral-model/targets/simple_switch/simple_switch_CLI
echo $$ > check_server.pid
while true
do
  >fail.txt
  >ok.txt
  for ip in `cat ip.txt`
  do
   {
     #ping -c1 -W1 $ip &>/dev/null
     mycode=`curl -m 1 -s -w %{http_code} http://$ip -o /dev/null`
     if [ "$mycode" -ne 200 ]; then
        echo $ip >> fail.txt
     else
        echo $ip >> ok.txt
     fi   
   }&
  done
  wait

  if [ -s fail.txt ];then
    for ip in `cat fail.txt`
    do
     #echo $ip
     if [ "$ip" = "172.17.0.2" ];then
        #echo "server1 fails"
        echo "table_modify set_status1 _fail1 0 1" | $CLI_PATH --thrift-port 9090 &>/dev/null
     elif [ "$ip" = "172.17.0.3" ];then
        #echo "server2 fails"
        echo "table_modify set_status2 _fail2 0 1" | $CLI_PATH --thrift-port 9090 &>/dev/null
     elif [ "$ip" = "172.17.0.4" ];then
        #echo "server3 fails"
        echo "table_modify set_status3 _fail3 0 1" | $CLI_PATH --thrift-port 9090 &>/dev/null
     elif [ "$ip" = "172.17.0.5" ];then
        #echo "server4 fails"
        echo "table_modify set_status4 _fail4 0 1" | $CLI_PATH --thrift-port 9090 &>/dev/null
     fi
    done
  fi

  if [ -s ok.txt ];then
    for ip in `cat ok.txt`
    do
     #echo $ip
     if [ "$ip" = "172.17.0.2" ];then
        #echo "server1 ok"
        echo "table_modify set_status1 _fail1 0 0" | $CLI_PATH --thrift-port 9090 &>/dev/null
     elif [ "$ip" = "172.17.0.3" ];then
        #echo "server2 ok"
        echo "table_modify set_status2 _fail2 0 0" | $CLI_PATH --thrift-port 9090 &>/dev/null
     elif [ "$ip" = "172.17.0.4" ];then
        #echo "server3 ok"
        echo "table_modify set_status3 _fail3 0 0" | $CLI_PATH --thrift-port 9090 &>/dev/null
     elif [ "$ip" = "172.17.0.5" ];then
        #echo "server4 ok"
        echo "table_modify set_status4 _fail4 0 0" | $CLI_PATH --thrift-port 9090 &>/dev/null
     fi
    done
  fi

  sleep 1
done
