/*
 * Here's a sample kernel module showing the use of jprobes to dump
 * the arguments of do_fork().
 *
 * For more information on theory of operation of jprobes, see
 * Documentation/kprobes.txt
 *
 * Build and insert the kernel module as done in the kprobe example.
 * You will see the trace data in /var/log/messages and on the
 * console whenever do_fork() is invoked to create a new process.
 * (Some messages may be suppressed if syslogd is configured to
 * eliminate duplicate messages.)
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>

/*
 * Jumper probe for do_fork.
 * Mirror principle enables access to arguments of the probed routine
 * from the probe handler.
 */

/* Proxy routine having the same arguments as actual do_fork() routine */

#define MAX_NAME 255

static int target_pid;
module_param(target_pid, int, 0);

static char func_name[MAX_NAME]="do_sys_open"; 

static long  entry_open_handler( int fdn, char * filename, int flags , umode_t mode)
{
	
	if (target_pid == current->pid) {
		printk("Process %s pid %d : ", current->comm, current->pid); 
		printk("OPEN filename= %s, flags=%x, mode=%x\n",  filename, flags, mode);
	}
	/* Always end with a call to jprobe_return(). */
	jprobe_return();
	return 0;
}

/*
 * Return-probe handler: Log the return value and duration. Duration may turn
 * out to be zero consistently, depending upon the granularity of time
 * accounting on the platform.
 */
static int exit_open_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval; 
  	
	if(target_pid == current->pid) { 
		retval=regs_return_value(regs); 
		printk("Process %s pid %d : ",current->comm, current->pid);  
		printk("OPEN returned %d \n",retval);
	}
    return 0;
    
} 


static struct jprobe my_jprobe = {
	.entry			= entry_open_handler,
	.kp = {
		.symbol_name = func_name,
	},
};


static struct kretprobe  my_kretprobe= {
    .handler = exit_open_handler, 
    .kp={   
        .symbol_name=func_name, 
    }   
};
   
    
static int __init probe_init(void)
{
	int ret;

	ret = register_jprobe(&my_jprobe);
	if (ret < 0) {
		printk(KERN_INFO "register_jprobe failed, returned %d\n", ret);
		return -1;
	}


	ret = register_kretprobe(&my_kretprobe);
	if (ret < 0) {
		printk(KERN_INFO "register_kretprobe failed, returned %d\n",
				ret);
		return -1;
	}

    printk(KERN_INFO "Planted return probe at %s: %p\n",
			my_kretprobe.kp.symbol_name, my_kretprobe.kp.addr);
	return 0;
}

static void __exit probe_exit(void)
{
	unregister_jprobe(&my_jprobe);
	printk(KERN_INFO "jprobe at %p unregistered\n", my_jprobe.kp.addr);


	unregister_kretprobe(&my_kretprobe);
	printk(KERN_INFO "kretprobe at %p unregistered\n",
			my_kretprobe.kp.addr);    
    
}

module_init(probe_init)
module_exit(probe_exit)
MODULE_LICENSE("GPL");
