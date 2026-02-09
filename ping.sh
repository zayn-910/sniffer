while true; do 
  choice=$((1 + RANDOM % 3)); 
  if [ $choice -eq 1 ]; then 
    echo "Sending ICMP..."; sudo hping3 -1 -c 1 --rand-source 192.168.1.1; 
  elif [ $choice -eq 2 ]; then 
    echo "Sending TCP (Port 80)..."; sudo hping3 -S -p 80 -d 40 -c 1 --rand-source -E /dev/stdin 192.168.1.1; 
  else 
    echo "Sending UDP (Port 53)..."; sudo hping3 --udp -p 53 -c 1 --rand-source 192.168.1.1; 
  fi; 
  sleep 1; 
done
