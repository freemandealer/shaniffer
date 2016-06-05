#ifndef RIP_H
#define RIP_H

#include <unistd.h>


struct rip_packet {
    __u8    cmd;
    __u8    ver;
    union {
        struct {
            __u16   zero1;
            __u16   addr_family;
            __u16   zero2;
            __u32   addr;
            __u32   zero3;
            __u32   zero4;
            __u32   metric;
        } v1;
        struct {
            __u8    used;
            __u16   addr_format;
            __u16   rt_tag;
            __u32   addr;
            __u32   subnet_mask;
            __u32   nhop;
            __u32   metric;
        } v2;
    } u;
};

#endif
