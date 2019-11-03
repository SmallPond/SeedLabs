
static char secret[8] = {’S’, ’E’, ’E’, ’D’, ’L’, ’a’, ’b’, ’s’};
static struct proc_dir_entry *secret_entry;
static char* secret_buffer;

static int test_proc_open(struct inode *inode, struct file *file)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,0,0)
    return single_open(file, NULL, PDE(inode)->data);
#else
    return single_open(file, NULL, PDE_DATA(inode));
#endif
}

tatic ssize_t read_proc(struct file *filp, char *buffer,
size_t length, loff_t *offset)
{
    memcpy(secret_buffer, &secret, 8);// ➀
    return 8;
}

static const struct file_operations test_proc_fops = 
{
    .owner = THIS_MODULE,
    // redirect  reconstruct
    .open = test_proc_open,
    .read = read_proc,
    .llseed = seq_lseek,
    .release = single_release,
};


static __init int test_proc_init(void) 
{
    // write message in kernel message buffer
    printk("secret data address:%p\n", &secret); // ➁
    secret_buffer = (char*)vmalloc(8);

    // create data entry in /proc
    secret_entry = proc_create_data("secret_data",0444, NULL, &test_proc_fops, NULL); // ➂
    if (secret_entry) return 0;
    return -ENOMEM;

}

static __exit void test_proc_cleanup(void)
{
    remove_proc_entry("secret_data", NULL);
}

module_init(test_proc_init);
module_exit(test_proc_cleanup);




