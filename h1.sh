VOLUMES=(2 5 10 20 50 100)

for x in {1..1000}
do
	RANDOM=$$$(date +%s)
	volume=${VOLUMES[$RANDOM % ${#VOLUMES[@]}]}
	suffix="M"
	var="$volume$suffix"
	echo "iperf -c 10.0.0.2 -p $((5000 + x)) -n $var &"
	iperf -c 10.0.0.2 -p $((5000 + x)) -n $var &
	sleep 0.05
done
