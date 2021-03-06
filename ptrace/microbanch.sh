#!/bin/bash 

logfile=micro.txt
sample=./sample
tracer=./tracer
timer=/usr/bin/time 
system_call_number=100000

name=("ptrace" "proc" "cross memory");
tracer_options=('-m 0' '-m 1' '-m 2');
		
echo -n >$logfile


for buffer_size in 1 2 8 16 32 64 128 256 512 1024 2048 4096 9192
do
     
      for arg  in 0 1 2 
      do
      echo "Buffer Size : $buffer_size  Memory access via : ${name[$arg]}" >> $logfile; 
      echo $tracer -m $arg $sample $buffer_size $system_call_number >> $logfile;
      $timer --output=$logfile --append $tracer -m $arg $sample $buffer_size $system_call_number ;
      
      done
done
