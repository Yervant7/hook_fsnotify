#include <common.h>
#include <compiler.h>
#include <hook.h>
#include <log.h>
#include <kpmodule.h>
#include <kputils.h>
#include <ktypes.h>
#include <kallsyms.h>
#include <ksyms.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>

KPM_NAME("hook_fsnotify");
KPM_VERSION("1.1.0");
KPM_LICENSE("MIT");
KPM_AUTHOR("Yervant7");
KPM_DESCRIPTION("A KernelPatch Module (KPM) for Hooking fsnotify, for Linux 5.10 to 6.12");

#define YV_TAG "[hook-fsnotify] "

#define yv_info(fmt, ...) logki(YV_TAG fmt, ##__VA_ARGS__)
#define yv_debug(fmt, ...) logkd(YV_TAG fmt, ##__VA_ARGS__)
#define yv_error(fmt, ...) logke(YV_TAG fmt, ##__VA_ARGS__)

static bool init_error = false;
static bool hook_active = false;
static unsigned long fsnotify_addr = 0;

#define hkfunc_match(func)                                                     \
kfunc_lookup_name(func);                                                     \
if (!kf_##func) {                                                            \
    yv_error("Failed to find kfunc %s\n", #func);                              \
    init_error = true;                                                         \
};

long kfunc_def(copy_from_kernel_nofault)(void *dst, const void *src, size_t size);

struct inode;

#define PROC_SUPER_MAGIC	0x9fa0

// gki 5.10 to 6.12 same offset
#define SUPER_BLOCK_OFF 40
#define MAGIC_OFF 96

/* Helper string and userspace response utilities */
static inline int kpm_isspace(char c) {
    return (c == ' ' || c == '\t' || c == '\n' || c == '\r');
}

static const char *kpm_skip_spaces(const char *s) {
    if (!s) return "";
    while (*s && kpm_isspace(*s)) s++;
    return s;
}

static bool kpm_streq(const char *s1, const char *s2) {
    if (!s1 || !s2) return false;
    while (*s1 && *s2) {
        if (*s1 != *s2) return false;
        s1++;
        s2++;
    }
    while (*s1 && kpm_isspace(*s1)) s1++;
    return (*s1 == '\0' && *s2 == '\0');
}

static void send_user_msg(char __user *out_msg, int outlen, const char *msg) {
    if (!out_msg || outlen <= 0 || !msg) return;
    int len = 0;
    while (msg[len] && len < outlen - 1) {
        len++;
    }
    compat_copy_to_user(out_msg, msg, len + 1);
}

/*
int fsnotify(__u32 mask, const void *data, int data_type, struct inode *dir, const struct qstr *file_name, struct inode *inode, u32 cookie)
*/

static void before_fsnotify(hook_fargs7_t *args, void *udata) {
    if (!hook_active) return;
    if (!args) return;
    
    struct inode *dir = (struct inode *)args->arg3;
    struct inode *inode = (struct inode *)args->arg5;
    struct inode *target = inode ? inode : dir;
    
    if (!target) return;
    if (!kfunc(copy_from_kernel_nofault)) return;
    
    unsigned long sb_ptr = 0;
    
    if (kfunc(copy_from_kernel_nofault)(&sb_ptr, (char *)target + SUPER_BLOCK_OFF, sizeof(sb_ptr)) != 0) {
        return; 
    }
    
    if (sb_ptr) {
        unsigned long magic = 0;
        
        if (kfunc(copy_from_kernel_nofault)(&magic, (char *)sb_ptr + MAGIC_OFF, sizeof(magic)) != 0) {
            return;
        }
        
        if (magic == PROC_SUPER_MAGIC) {
            yv_debug("fsnotify ignored for /proc\n");
            args->skip_origin = 1;
            args->ret = 0;
        }
    }
}

static long module_init_handler(const char *args, const char *event, void *__user reserved)
{
    if (kver < VERSION(5, 10, 0)) {
        yv_error("Kernel versions prior to 5.10 don't need this, aborting...\n");
        return -1;
    }
    
    hkfunc_match(copy_from_kernel_nofault);
    if (init_error) {
        yv_error("Symbol resolution failed, aborting hook\n");
        return -ENOENT;
    }
    
    fsnotify_addr = kallsyms_lookup_name("fsnotify");
    if (!fsnotify_addr) {
        yv_error("fsnotify_addr not found\n");
        return -ENOENT;
    }
    
    hook_err_t ret = hook_wrap7((void *)fsnotify_addr, before_fsnotify, 0, 0);
    if (ret) {
        yv_error("hook installation failed: %d\n", ret);
        return -EFAULT;
    }
    
    yv_info("hook installed successfully\n");
    return 0;
}

static long module_control_handler(const char *args, char __user *out_msg, int outlen) {
    const char *cmd = kpm_skip_spaces(args);
    long ret = 0;
    
    if (kpm_streq(cmd, "enable") || kpm_streq(cmd, "on") || kpm_streq(cmd, "start") || kpm_streq(cmd, "1")) {
        hook_active = true;
        send_user_msg(out_msg, outlen, "hook_fsnotify: enabled\n");
    } else if (kpm_streq(cmd, "disable") || kpm_streq(cmd, "off") || kpm_streq(cmd, "stop") || kpm_streq(cmd, "0")) {
        hook_active = false;
        send_user_msg(out_msg, outlen, "hook_fsnotify: disabled\n");
    } else if (kpm_streq(cmd, "status") || kpm_streq(cmd, "state") || kpm_streq(cmd, "get")) {
        if (hook_active) {
            send_user_msg(out_msg, outlen, "hook_fsnotify: active\n");
        } else {
            send_user_msg(out_msg, outlen, "hook_fsnotify: inactive\n");
        }
    } else if (kpm_streq(cmd, "toggle")) {
        if (hook_active) {
            hook_active = false;
            send_user_msg(out_msg, outlen, "hook_fsnotify: toggled to disabled\n");
        } else {
            hook_active = true;
            send_user_msg(out_msg, outlen, "hook_fsnotify: toggled to enabled\n");
        }
    } else {
        yv_info("unknown control command: '%s'\n", cmd ? cmd : "(null)");
        send_user_msg(out_msg, outlen, "unknown command. Available: enable | disable | status | toggle\n");
        ret = -EINVAL;
    }
    
    return ret;
}

static long module_cleanup_handler(void *__user reserved) {
    hook_unwrap((void *)fsnotify_addr, before_fsnotify, 0);
    yv_info("hook uninstalled and cleaned up\n");
    return 0;
}

KPM_INIT(module_init_handler);
KPM_CTL0(module_control_handler);
KPM_EXIT(module_cleanup_handler);
