# ztlsm
Zero Trust LSM. It is created for a chapter of a new book 《Linux内核安全实战》.

Usages:
1. in Linux kernel source tree (>=6.8), under security, create directory "ztlsm".
2. copy this project's files Kconfig, Makefile, and ztlsm.c into the directory "ztlsm".
3. modify security/Kconfig, add one line:
          source "security/ztlsm/Kconfig"
4.  modify include/uapi/linux/lsm.h, add one line:
          #define LSM_ID_ZTLSM           111
5. make kernel 
