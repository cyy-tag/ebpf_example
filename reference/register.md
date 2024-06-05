## eBPF has 10 general purpose registers and a read-only frame pointer register, all of which are 64-bits wide.

+ R0: return value from function calls, and exit value for eBPF programs

+ R1 - R5: arguments for function calls

+ R6 - R9: callee saved registers that function calls will preserve

+ R10: read-only frame pointer to access stack

