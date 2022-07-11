#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/list.h>
#include <linux/sched/signal.h>
#include <linux/timer.h>

// Pull in headers from the tpm char device used in the kernel
#include <linux/tpm.h>

#include <axiado_types.h>
#include <tpm2_axiado.h> // Include our own tpm2 header
#include <tpm2_driver.h>

MODULE_LICENSE("Proprietary");
MODULE_AUTHOR("rean.griffith@axiado.com");
MODULE_DESCRIPTION("vTPM TPM2 Compat");
MODULE_VERSION("0.01");

#define DEVICE_NAME "tpm2_compat"
#define DEVICE_NODE_NAME "tpm2_compat"

// Client response wait q
DECLARE_WAIT_QUEUE_HEAD(vtpm_client_wait_q);
// Server work wait q
DECLARE_WAIT_QUEUE_HEAD(vtpm_server_work_q);

/* Device function prototypes */
static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char *, size_t, loff_t *);

static int major_num = 0;
static int device_open_count = 0;
static struct timer_list pulse_timer;
//static bool debug = false;

// List data structures
LIST_HEAD(op_request_q);
LIST_HEAD(op_response_q);

/* Wire-up device function pointers */
static struct file_operations file_ops = {
 .owner = THIS_MODULE,
 .read = device_read,
 .write = device_write,
 .open = device_open,
 .release = device_release
};

typedef struct axiado_vtpm {
    /* Mutual exclusion semaphore */
    struct semaphore wait_sem;
    /* We need a wait_q so callers can block when necessary */
} vTPM;

static vTPM instance;

void
pulse_timer_cb(struct timer_list *timer) {
    // Wake up any sleeping server or client processs to avoid deadlock
    // (server and client(s) simultaneously asleep due to missed
    // wake ups
    wake_up_all(&vtpm_server_work_q);
    // Wake up any sleeping clients unless we want to debug deadlock
    wake_up_all(&vtpm_client_wait_q);
    // Re-initialize the timer for 5 seconds into the future
    mod_timer(&pulse_timer, jiffies + msecs_to_jiffies(300));
}

/* Device reads */
static ssize_t
device_read(struct file *file,
            char *buffer,
            size_t len,
            loff_t *offset) {
    ssize_t ret = -EOPNOTSUPP;
    char *data_buf = NULL;
    uint16_t magic_num = 0;
    DEFINE_WAIT(wait);

    // When we see a read operation it may not come with a header
    // mainly because callers that write commands to a TPM device
    // are the only owners and are essentialy reading for a response
    // to their last command

    // We'll distinguish things based on the first two bytes of the read buffer
    // if it's "something special" (TPM2_ST_AXIADO) then we'll treat it like an
    // Axiado-specific command otherwise it's a regular TPM 2.0 read

    /*
    printk(KERN_INFO "[AXIADO_TPM2_COMPAT] [pid: %d] Device read request. " \
    	     "Size: %ld, offset: %lld", current->pid, len, *offset);
    */

    // The read buffer needs to be at least 2 bytes otherwise reject it
    if (len < sizeof(uint16_t)) {
        ret = -EAGAIN;
        goto exit_device_read_unlocked;
    }

    // Alloc a buffer
    data_buf = kmalloc(len, GFP_KERNEL);
    if (!data_buf) {
        printk(KERN_ALERT "[AXIADO_TPM2_COMPAT] Unable to allocate "\
               "%ld bytes", len);
        return -ENOMEM;
    }
    // Zero out buffer
    memset(data_buf, 0, len);
    // Copy user-space buffer into kernel buffer
    if (copy_from_user(data_buf, buffer, len) != 0) {
        printk(KERN_ALERT "[AXIADO_TPM2_COMPAT] Unable to copy bytes "\
               "from userspace buffer to kernel buffer");
        ret = -EFAULT;
        goto exit_device_read_unlocked;
    }

    // Lock the driver
    ret = 0;
    while (ret == 0) {
        // Grab the semaphore to lock the driver and put the request onto the op queue
        if (down_interruptible(&instance.wait_sem)) {
            ; // Sleep if there's contention
        }

        memcpy(&magic_num, data_buf, sizeof(uint16_t));
        if (magic_num == TPM2_ST_AXIADO) {
            ; // Handle Axiado-specific command
            ret = handle_ax_tpm20_read_locked(data_buf, len);
        } else {
            ; // Handle TPM2.0 operation
            ret = handle_tpm20_read_locked(data_buf, len);
        }

        if (ret == -MUST_SLEEP) {
            //printk(KERN_INFO "[AXIADO_TPM2_COMPAT] Putting process (pid: %d) to sleep after empty read\n", current->pid);
            // Put this process to sleep and yield the processor - unlock the driver first
            // Release the semaphore
            up(&instance.wait_sem);
            // Wake up any sleeping server processes
            wake_up_all(&vtpm_server_work_q);

            // Set our state to task interruptible so we can
            // yield the CPU and be put to sleep
            prepare_to_wait(&vtpm_client_wait_q, &wait, TASK_INTERRUPTIBLE);
            // Are there any signals pending if so we're unlocked so ask for
            // the system call to be restarted
            if (signal_pending(current)) {
                ret = -EINTR;
                // If we get interrupted while sleeping, remove ourselves from the
                // the wait queues before we leave otherwise we'll hang and be unable to
                // clean up and let the userspace caller cleanup completely
                finish_wait(&vtpm_client_wait_q, &wait);
                goto exit_device_read_unlocked;
            }
            //printk(KERN_INFO "[AXIADO_TPM2_COMPAT] Process (pid: %d) yielding after empty read\n", current->pid);
            // Let the scheduler pick another process to run
            schedule();
            //printk(KERN_INFO "[AXIADO_TPM2_COMPAT] Process (pid: %d) running again after yield\n", current->pid);
            // We're running again so remove ourselves from the wait list
            finish_wait(&vtpm_client_wait_q, &wait);
            ret = 0; // Set to 0 so we retry looking for things to read
        }

        // If any bytes were read and written to data_buf then copy to user
        if (ret > 0) {
            if (copy_to_user(buffer, data_buf, ret)) {
                // Bail if we could not copy from kernel buffer to user buffer
                printk(KERN_ALERT "[AXIADO_TPM2_COMPAT] Unable to copy %ld byte(s) from kernel buffer to user buffer\n", ret);
                ret = -EFAULT;
                goto exit_device_read_locked;
            }
        }
    } // Retry-read loop (in case we have to sleep and yield)
 exit_device_read_locked:
    // Release the semaphore and unlock the driver
    up(&instance.wait_sem);
 exit_device_read_unlocked:
    if (data_buf) {
        kfree(data_buf);
        data_buf = NULL;
    }
    return ret;
}

static ssize_t
device_write(struct file *file,
             const char *buffer,
             size_t len,
             loff_t *offset) {
    // Function-wide variables
    ssize_t ret = -EOPNOTSUPP;
    char *data_buf = NULL;
    uint16_t magic_num = 0;
    tpm2_op_driver_request *request = NULL;

    /*
    printk(KERN_INFO "[AXIADO_TPM2_COMPAT] [pid: %d] Device write request. " \
           "Size: %ld, offset: %lld", current->pid, len, *offset);
    */
    // We expect writes to at least be two bytes
    if (len < sizeof(uint16_t)) {
        ret = -EAGAIN;
        goto exit_device_write_unlocked;
    }

    // Alloc a buffer
    data_buf = kmalloc(len, GFP_KERNEL);
    if (!data_buf) {
        printk(KERN_ALERT "[AXIADO_TPM2_COMPAT] Unable to allocate "\
               "%ld bytes", len);
        ret = -ENOMEM;
        goto exit_device_write_unlocked;
    }
    // Zero out buffer
    memset(data_buf, 0, len);

    // Copy user-space buffer into kernel buffer
    if (copy_from_user(data_buf, buffer, len) != 0) {
        printk(KERN_ALERT "[AXIADO_TPM2_COMPAT] Unable to copy bytes "\
               "from userspace buffer to kernel buffer");
        ret = -EFAULT;
        goto exit_device_write_unlocked;
    }

    request = kmalloc(sizeof(*request), GFP_KERNEL);
    if (!request) {
        ret = -ENOMEM;
        goto exit_device_write_unlocked;
    }
    // Zero out request structure
    memset(request, 0, sizeof(*request));

    // Lock the driver
    // Grab the semaphore to lock the driver and put the request onto the op queue
    if (down_interruptible(&instance.wait_sem)) {
        ; // Sleep if there's contention
    }

    // Check whether we need to treat this request like a standard TPM2.0 command
    // or an Axiado-specific command
    memcpy(&magic_num, data_buf, sizeof(uint16_t));
    if (magic_num == TPM2_ST_AXIADO) {
        ; // Handle Axiado-specific command
        ret = handle_ax_tpm20_write_locked(data_buf, len);
        // If we wrote everything we expected to write then
        // wake up any sleeping clients so they can check
        // whether their requests have responses pending
        if (ret == len) {
            wake_up_all(&vtpm_client_wait_q);
        }
        goto exit_device_write_locked;
    } else {
        // Handle TPM 2.0 Operation
        ret = handle_tpm20_write_locked(data_buf, len);
        // Everything worked so wake up any sleeping servers
        if (ret == len) {
            wake_up_all(&vtpm_server_work_q);
        }
        goto exit_device_write_locked;
    }

 exit_device_write_locked:
    // Release the semaphore and unlock the driver
    up(&instance.wait_sem);
 exit_device_write_unlocked:
    if (data_buf) {
        kfree(data_buf);
        data_buf = NULL;
    }
    return ret;
}

/* Device open */
static int
device_open(struct inode *inode, struct file *file) {
    printk(KERN_INFO "[AXIADO_TPM2_COMPAT] Device open request");

    // Multiple processes can open this device at the same time
    // We'll synchronize reads and writes, but we also will synchronize
    // the device reference counts
    if (down_interruptible(&instance.wait_sem)) {
        // Sleep if there's contention
    }

    device_open_count++;
    try_module_get(THIS_MODULE);

    up(&instance.wait_sem);
    return 0;
}

/* Device close */
static int
device_release(struct inode *inode, struct file *file) {
    printk(KERN_INFO "[AXIADO_TPM2_COMPAT] Device close request");

    if (down_interruptible(&instance.wait_sem)) {
        ; // Sleep if there's contention
    }

    device_open_count--;
    module_put(THIS_MODULE);

    up(&instance.wait_sem);
    return 0;
}

static int
__init vtpm_driver_init(void) {
    int result = 0;
    // Initialize vTPM struct fields, especially the synchronization primitives
    sema_init(&instance.wait_sem, 1);
    // Try to get the semaphore
    if (down_interruptible(&instance.wait_sem)) {
        // Sleep if the semaphore is contended - which it should not be on init
    }

    /* Critical section */
    if (major_num == 0) {
        printk(KERN_INFO "[AXIADO_TPM2_COMPAT] Loaded TPM2 Compat Driver!\n");
        major_num = register_chrdev(0, DEVICE_NAME, &file_ops);
        if (major_num < 0) {
            // If register fails the value returned is negative
            // so we want to return that value from this routine.
            printk(KERN_ALERT "[AXIADO_TPM2_COMPAT] Could not register device: %d\n",
                   major_num);
            result = major_num;
            goto exit_tpm_init;
        } else {
            printk(KERN_INFO "[AXIADO_TPM2_COMPAT] Module loaded with device major number %d\n",
                   major_num);
            // Print a helpful message on how to link this device to a
            // node in the device tree using the major number
            printk(KERN_INFO "[AXIADO_TPM2_COMPAT] sudo mknod /dev/%s c %d 0",
                   DEVICE_NODE_NAME, major_num);
            // Command to make the device world writable and readable
            // so anyone can use it to request operations
            printk(KERN_INFO "[AXIADO_TPM2_COMPAT] sudo chmod o+rw /dev/%s",
                   DEVICE_NODE_NAME);
        }
    }

    // Set up pulse timer to run every 5 seconds
    // (use 5 secs to start => 12 pulses per minute => 720 per hour => 17,280 per day)
    timer_setup(&pulse_timer, pulse_timer_cb, 0);
    result = mod_timer(&pulse_timer, jiffies + msecs_to_jiffies(300));
    if (result) {
        printk(KERN_ALERT "[AXIADO_TPM2_COMPAT] Unable to set up pulse timer\n");
    }

 exit_tpm_init:
    // Release the semaphore
    up(&instance.wait_sem);
    // If register worked, then result should still be 0 so we return that
    return result;
}

static void
__exit vtpm_driver_exit(void) {
    // Try to get the semaphore
    if (down_interruptible(&instance.wait_sem)) {
        // Sleep if the semaphore is contended
    }

    // Unregister char device
    if (major_num != 0) {
        int num_orphaned_requests = 0;
        int num_unclaimed_responses = 0;

        tpm2_op_driver_request *current_req, *next_req;
        tpm2_op_driver_response *current_resp, *next_resp;

        unregister_chrdev(major_num, DEVICE_NAME);
        printk(KERN_INFO "[AXIADO_TPM2_COMPAT] Unloading Axiado TPM2 Compat Driver!\n");

        // Clean up queues
        list_for_each_entry_safe(current_req, next_req,
                                 &op_request_q, list) {
            // Remove the entry from the list
            list_del(&current_req->list);

            // Free the buffer in the request
            if (current_req->op_request.buf) {
                kfree(current_req->op_request.buf);
                current_req->op_request.buf = NULL;
            }

            // Free the memory for the removed struct
            kfree(current_req);
            num_orphaned_requests++;
        }

        list_for_each_entry_safe(current_resp, next_resp,
                                 &op_response_q, list) {
            // Remove entry from the list
            list_del(&current_resp->list);
            // Free any buffer in the response
            if (current_resp->op_response.buf) {
                kfree(current_resp->op_response.buf);
                current_resp->op_response.buf = NULL;
            }
            // Free the memory for the removed struct
            kfree(current_resp);
            num_unclaimed_responses++;
        }

        printk(KERN_INFO "[AXIADO_TPM2_COMPAT] Unload module: %d orphaned request(s), %d unclaimed response(s)\n",
               num_orphaned_requests, num_unclaimed_responses);
        // After we unreigster the device set the major_num to 0 so that
        // anyone coming afterwards won't try to unregister an already
        // unregistered device
        major_num = 0;
    }

    if (del_timer(&pulse_timer)) {
        printk(KERN_ALERT "[AXIADO_TPM2_COMPAT] Pulse timer still in use at module unload time\n");
    }

    // Release the semaphore and leave
    up(&instance.wait_sem);
}

module_init(vtpm_driver_init);
module_exit(vtpm_driver_exit);
