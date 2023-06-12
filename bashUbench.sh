 ./ubench -g 2 -n 4 -s 0.0 1.0 -d 2 2 -t 0 1 2 3 -i 10000000 & 
var=$!
echo $!
echo "debug"

echo $var
taskset -pc 0,1,2,3 $var
sudo ./test 0 1 2 3 $var

