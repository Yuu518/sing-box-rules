#!/bin/bash

mkdir -p geoip
./mosdns v2dat unpack-ip -o ./geoip/ geoip.dat
list=($(ls ./geoip | sed 's/geoip_//g' | sed 's/\.txt//g'))
for ((i = 0; i < ${#list[@]}; i++)); do
	#	echo "${list[i]}"
	mv ./geoip/geoip_${list[i]}.txt ./geoip/${list[i]}.list
	echo "payload:" >./geoip/${list[i]}.yaml
	cat ./geoip/${list[i]}.list | sed 's/^/- "/g' | sed 's/$/"/g' >>./geoip/${list[i]}.yaml
done

mkdir -p geosite
./mosdns v2dat unpack-domain -o ./geosite/ geosite.dat
list=($(ls ./geosite | sed 's/geosite_//g' | sed 's/\.txt//g'))
for ((i = 0; i < ${#list[@]}; i++)); do
	#	echo "${list[i]}"
	mv ./geosite/geosite_${list[i]}.txt ./geosite/${list[i]}.list
	sed -i '/^#/d' geosite/${list[i]}.list
	sed -i '/^keyword:/d' geosite/${list[i]}.list
	sed -i '/^regexp:/d' geosite/${list[i]}.list
	sed -i 's/^/+./g' ./geosite/${list[i]}.list
	sed -i 's/+.full://g' ./geosite/${list[i]}.list
	sed -i 's/+.domain:/+./g' ./geosite/${list[i]}.list
	echo "payload:" >./geosite/${list[i]}.yaml
	cat ./geosite/${list[i]}.list | sed 's/^/- "/g' | sed 's/$/"/g' >>./geosite/${list[i]}.yaml
done
