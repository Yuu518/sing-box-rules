#!/bin/bash

./mosdns v2dat unpack-ip -o ./rule_set_ip/ geoip.dat
list=($(ls ./rule_set_ip | sed 's/geoip_//g' | sed 's/\.txt//g'))
for ((i = 0; i < ${#list[@]}; i++)); do
	sed -i 's/^/        "/g' ./rule_set_ip/geoip_${list[i]}.txt
	sed -i 's/$/",/g' ./rule_set_ip/geoip_${list[i]}.txt
	sed -i '1s/^/{\n  "version": 1,\n  "rules": [\n    {\n      "ip_cidr": [\n/g' ./rule_set_ip/geoip_${list[i]}.txt
	sed -i '$ s/,$/\n      ]\n    }\n  ]\n}/g' ./rule_set_ip/geoip_${list[i]}.txt
	mv ./rule_set_ip/geoip_${list[i]}.txt ./rule_set_ip/${list[i]}.json
	./sing-box rule-set compile "./rule_set_ip/${list[i]}.json" -o ./rule_set_ip/${list[i]}.srs
done

list=($(./sing-box geosite list | sed 's/ (.*)$//g'))
for ((i = 0; i < ${#list[@]}; i++)); do
	./sing-box geosite export ${list[i]} -o ./rule_set_site/${list[i]}.json
	./sing-box rule-set compile ./rule_set_site/${list[i]}.json -o ./rule_set_site/${list[i]}.srs
done
