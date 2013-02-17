/* Trace do_execv.  Taken basically from Documentation/kprobes.txt */
  #include <linux/kernel.h>
   #include <linux/module.h>
   #include <linux/sched.h>
   #include <linux/kprobes.h>
   #include <linux/kallsyms.h>
  
   /*
    * Pre-entry point for do_execve.
   */
  static int my_do_execve(char * filename,
                          char __user *__user *argv,
                          char __user *__user *envp,
                          struct pt_regs * regs)
  {
          printk("do_fork  for %s from %s\n", filename, current->comm);
          /* Always end with a call to jprobe_return(). */
          jprobe_return();
         /*NOTREACHED*/
          return 0;
 }
  
 static struct jprobe my_jprobe = {
          .entry = (kprobe_opcode_t *) my_do_execve
  };
  
  int init_module(void)
  {
          int ret;
          my_jprobe.kp.addr = 
                  (kprobe_opcode_t *) kallsyms_lookup_name("do_fork");
          if (!my_jprobe.kp.addr) {
                  printk("Couldn't find %s to plant jprobe\n", "do_fork");
                 return -1;
          }
  
          if ((ret = register_jprobe(&my_jprobe)) <0) {
                  printk("register_jprobe failed, returned %d\n", ret);
                  return -1;
          }
          printk("Planted jprobe at %p, handler addr %p\n",
                 my_jprobe.kp.addr, my_jprobe.entry);
         return 0;
 }
  
 void cleanup_module(void)
  {
          unregister_jprobe(&my_jprobe);
          printk("jprobe unregistered\n");
 }
 
  MODULE_LICENSE("GPL");
