path=$(pwd $1)\/
MYSQL='mysql -u root -D pdns -e'
for i in `ls $1`;
do
	#echo "$path$1$i"
	QUERY="load data infile '$path$1$i' into table dec14 fields terminated by ','  enclosed by '"'"'"' lines terminated by '\n' ignore 1 lines (count,rrtype,rrname,@var1,@var2,@var3,@var4,rdata) set zone_time_first=FROM_UNIXTIME(@var1), zone_time_last=FROM_UNIXTIME(@var2), time_first=FROM_UNIXTIME(@var3), time_last=FROM_UNIXTIME(@var4);"
	echo "executing "$QUERY
	eval $MYSQL '"$QUERY"'
done;

echo "Done!"
