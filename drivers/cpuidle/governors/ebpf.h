#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, void *);
} idle_governor_map SEC(".maps");

SEC("replacement")
int new_idle_governor(int drv, int dev)
{
    void *func;

    // Load the function pointer from the BPF map
    func = bpf_map_lookup_elem(&idle_governor_map, 0); // Use index 0 for the single entry in the array

    // Call the loaded function pointer
    if (func)
        return ((int (*)(int, int))func)(drv, dev);

    // Return an error code if the function pointer is NULL
    return -1;
}
