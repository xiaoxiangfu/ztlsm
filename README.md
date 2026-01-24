# ztlsm
Zero Trust LSM. It is created for a chapter of a new book 《Linux内核安全实战》.

Usages:
1. in Linux kernel source tree (>=6.8), under security, create directory "ztlsm".
2. copy this project's files Kconfig, Makefile, and ztlsm.c into the directory just created.
3. modify security/Kconfig, add one line, like this:
diff --git a/security/Kconfig b/security/Kconfig
index 52c9af08ad35..7ac95684ac7b 100644
--- a/security/Kconfig
+++ b/security/Kconfig
@@ -194,6 +194,7 @@ source "security/yama/Kconfig"
 source "security/safesetid/Kconfig"
 source "security/lockdown/Kconfig"
 source "security/landlock/Kconfig"
+source "security/ztlsm/Kconfig"

 source "security/integrity/Kconfig"

4.  modify include/uapi/linux/lsm.h, add one line, like this:
diff --git a/include/uapi/linux/lsm.h b/include/uapi/linux/lsm.h
index f8aef9ade549..63435cefa46d 100644
--- a/include/uapi/linux/lsm.h
+++ b/include/uapi/linux/lsm.h
@@ -62,6 +62,7 @@ struct lsm_ctx {
 #define LSM_ID_LOCKDOWN                108
 #define LSM_ID_BPF             109
 #define LSM_ID_LANDLOCK                110
+#define LSM_ID_ZTLSM           111

5. make kernel 
