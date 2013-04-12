#!/bin/bash 


logfile="log.txt"; 
timer=/usr/bin/time 

echo -n >$logfile

test_programs=("ls"
		"dd if=/dev/zero of=/dev/null ibs=10024 count=1024k"
		"tar -czf audio.tar.gz  audio.MP3"
		); 


for current_test  in "${test_programs[@]}"
    do
      for soft in "" "./tracer" "./tracer"
      do
      echo $soft $current_test >> $logfile;
      $timer --output=$logfile --append $current_test;
      done
done
