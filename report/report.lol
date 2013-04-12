\contentsline {lstlisting}{\numberline {2.1}Synopsis ptrace system call}{5}
\contentsline {lstlisting}{\numberline {2.2}Parent and real parent fields with task\_struct Linux}{7}
\contentsline {lstlisting}{\numberline {2.3}Condition that identifies SIGTRAP signals}{7}
\contentsline {lstlisting}{\numberline {2.4}Condition that identifies exclusively system call entry and exit}{8}
\contentsline {lstlisting}{\numberline {2.5}Linux structures representing the general purpose registers of x64 CPU}{8}
\contentsline {lstlisting}{\numberline {2.6}Linux structure representing the general purpose registers of x32 CPU}{8}
\contentsline {lstlisting}{\numberline {2.7}Function which retrieve a buffer of size count from the tracee memory. Note, the value retrivied by a single ptrace call has to be converted to the char type before being inserted in the buffer.}{10}
\contentsline {lstlisting}{\numberline {2.8}Function which retrieve a buffer of size count from the tracee memory using the proc interface.}{12}
\contentsline {lstlisting}{\numberline {2.9}Function which retrieve a buffer of size count from the tracee memory using cross memory attach method.}{12}
\contentsline {lstlisting}{\numberline {3.1}Synopsis utrace\_attached\_engine}{17}
\contentsline {lstlisting}{\numberline {3.2}Synopsis utrace\_set\_events\_task}{17}
\contentsline {lstlisting}{\numberline {4.1}Write system call invocation via interrupt on x86\_32 architecture}{24}
\contentsline {lstlisting}{\numberline {4.2}Write system call invocation via VDSO gate on x86\_32 architecture.Note that the offset may change in a different platform.}{24}
\contentsline {lstlisting}{\numberline {4.3}Write system call invocation via syscall on x64 architecture.}{25}
\contentsline {lstlisting}{\numberline {4.4}Original instructions, x64 architecture}{27}
\contentsline {lstlisting}{\numberline {4.5}Instructions after the rewriting process using a relocation code approach at functional level}{27}
\contentsline {lstlisting}{\numberline {4.6}Wrapper \_\_libc\_start\_main used in seccomp-nurse}{33}
\contentsline {lstlisting}{\numberline {4.7}Synopsis utrace\_set\_events\_task}{35}
\contentsline {lstlisting}{\numberline {4.8}Request for entering seccomp filtering mode}{35}
\contentsline {lstlisting}{\numberline {4.9}BPF filter ensuring that a program can write only over the standard output}{36}
