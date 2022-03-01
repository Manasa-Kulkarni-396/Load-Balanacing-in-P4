#!/bin/bash
thread=5
tmp_fifofile=/tmp/$$.fifo

mkfifo $tmp_fifofile
exec 8<> $tmp_fifofile
rm $tmp_fifofile

ok=/tmp/ok.txt
fail=/tmp/fail.txt
>$ok
>$fail

for i in `seq $thread`
do
        echo >&8
done

for i in {1..1000}
do
        read -u 8
        {
        curl http://10.0.0.1/a.htm &>/dev/null
        if [ $? -eq 0 ]; then  
                echo "curl ok" >> $ok
        else
                echo "curl fail" >> $fail
        fi
        echo >&8
        }&
done
wait
exec 8>&-
echo "all finish..."
yes=`wc -l $ok`
no=`wc -l $fail`
echo "ok:" $yes
echo "fail:" $no
