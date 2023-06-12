python3 thread2.py &
var=$!
echo $!
echo "debug"

echo $var
taskset -pc 0,1,2,3 $var
sudo ./test 0 1 2 3 $var

