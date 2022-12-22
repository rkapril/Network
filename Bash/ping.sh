#!/bin/bash
cat /dev/null > ping.txt

is_alive_ping()
{
  ping -c 1 -w 1 $1 > /dev/null
  if [ $? -eq 0 ] 
  then
  echo $i: Used
  else
  echo $i: Available 
  fi
}

for i in 192.168.0.{1..254}
do
is_alive_ping $i &
done > ping.txt