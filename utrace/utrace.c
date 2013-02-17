#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/utrace.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/regset.h>


MODULE_DESCRIPTION("System call interceptor");
MODULE_LICENSE("GPL");

//Target pid
static int target_pid; 
module_param(target_pid, int, 0);

//#define TRACED_EVENTS (UTRACE_EVENT((SYSCALL_ENTRY) | UTRACE_EVENT(SYSCALL_EXIT)))
#define MY_EVENTS (UTRACE_EVENT(SYSCALL_ENTRY) | UTRACE_EVENT(SYSCALL_EXIT) )

#define __KERNEL__

static u32 intercept_system_call_entry( u32 action, struct utrace_engine * engine, struct pt_regs * regs) { 
		
		struct pid *pid_struct;
		struct task_struct *task; 
		int syscall_number;
		
		
/*		pid_struct = find_get_pid(target_pid);

                if(pid_struct == NULL)  {
                        printk("Errore removing utrace pid_struct");
                        return -1;
                }

                task =pid_task(pid_struct,PIDTYPE_PID);

                if (task==NULL) {
                        printk("Error removing utrace pid_task");
                        return -1;
                }


		printk("System call entry:  %d", task->pid); 
		syscall_number=syscall_get_nr (task, regs); 

		if(syscall_number < 0)  { 
                        printk("Errorr retrieving system call number ");
                        return -1;
                }
*/
		printk("System call number %d\n", regs->ax); 
				
		return UTRACE_RESUME;	
	}

	static u32 intercept_system_call_exit( u32 action, struct utrace_engine * engine, struct pt_regs * regs) { 
		printk("Process call exit %d\n", regs->ax); 
		return UTRACE_RESUME; 	
	}

static const struct utrace_engine_ops intercept_ops =
	{
		.report_syscall_entry= intercept_system_call_entry,
		.report_syscall_exit= intercept_system_call_exit, 
	};



static int __exit exit_system_call_interception() { 
		
		int ret;
		struct task_struct *target; 
		struct utrace_engine *engine;	
		struct pid * pid_struct;

		printk("Removing Utrace tracing mechanism from thread %d\n", target_pid); 
		
			
		pid_struct = find_get_pid(target_pid);
	
		if(pid_struct == NULL) 	{
			printk("Errore removing utrace pid_struct"); 
			return -1;
		}

		target =pid_task(pid_struct,PIDTYPE_PID);

		if (target ==NULL) {
			printk("Error removing utrace pid_task"); 
			return -1;	
		}
		
		engine=utrace_attach_task(target, UTRACE_ATTACH_MATCH_OPS,
			      &intercept_ops, 0);
		
		if (engine== NULL) { 
			printk("Errore removing utrace attaching engine"); 
			return -1;	
		} 

		ret = utrace_control(target, engine, UTRACE_DETACH);
        	if (ret == -EINPROGRESS) {
			printk("Utrace busy"); 
		}
             
                utrace_engine_put(engine);

		return 0;
	}



	static int __init init_system_call_interception() { 
		
		struct task_struct *target;
		struct utrace_engine *engine;
		struct pid * pid_struct; 
		int ret; 
	
		printk("Utrace tracing mechanism\n"); 
		printk("Target process %d\n", target_pid);
		
		//retrieve the process's task structur 
		//target=find_task_by_vpid(target_pid); 

		pid_struct = find_get_pid(target_pid);
		
		if(pid_struct == NULL) {
			printk("cannot find PID %d\n", target_pid);
			return -ECHILD;
		}

		target =pid_task(pid_struct,PIDTYPE_PID);

                if (target == NULL) {
                        printk("cannot find PID %d\n", target_pid);
                        return -ESRCH;
                }
		
	
		engine=utrace_attach_task(target, UTRACE_ATTACH_CREATE,&intercept_ops, 0);
		
		if (IS_ERR(engine))
			printk("utrace_attach: %ld\n", PTR_ERR(engine));
		else if (engine == NULL)
			printk("utrace_attach => null!\n");
		else
		printk("attached to %d => 0x%p\n", target->pid, engine);

		ret=utrace_set_events_pid(pid_struct, engine, MY_EVENTS);
		
		if (ret == -ESRCH)
			printk("pid %d died during setup\n", pid_vnr(pid_struct));
		else
			WARN_ON(ret);

		put_pid(pid_struct);
		if (engine && !IS_ERR(engine))
			utrace_engine_put(engine);
		
	
		return 0;
	
	
}

module_init(init_system_call_interception);
module_exit(exit_system_call_interception);
