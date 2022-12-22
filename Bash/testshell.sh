#!/bin/bash
array=("199.223.232.0" "8.8.8.8")
out=""
for i in "${array[@]}"; do
p=`ping ${i}`
out="${out} ${p}"
out="${out} \n"
done
printf "${out}"
printf "${out}" > ips.txt