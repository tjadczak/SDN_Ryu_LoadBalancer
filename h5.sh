for x in {1..1000}
do
	iperf -s -p $((5000 + x)) &
done
