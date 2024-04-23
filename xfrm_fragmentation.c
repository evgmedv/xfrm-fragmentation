/*
 *	Problem
 *	There is IPSEC encrypted channel. Traffic contains big UDP packets that
 *	must be fragmented before transmitting. By default Linux encrypts packets
 *	and then performs fragmentation of the encrypted packet. So we get
 *	fragmented ESP packets on output.
 *	Equipment on the other channel side does not understand fragmented ESP
 *	packets.
 *
 *	Task
 *	1. Create kernel module that fragments packets before encryption to get
 *	all ESP packets are not fragmented.
 *	2. Allow to enable/disable from user-space using /sys FS
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <net/dst.h>
#include <net/ip.h>
#include <net/xfrm.h>

static int do_fragment_xfrm = 0; /* Flag to enable/disable fragmentation */

static struct nf_hook_ops nfho;

/* Function to handle packets */
unsigned int do_xfrm_fragmentation(void *priv, struct sk_buff *skb,
				   const struct nf_hook_state *state)
{
    struct udphdr *udph;
    struct iphdr *iph;
    struct dst_entry *dst;
    int err = 0;
    unsigned int mtu;

    if (!skb || !do_fragment_xfrm)
        return NF_ACCEPT;

    iph = ip_hdr(skb);

    if (iph && iph->protocol == IPPROTO_UDP) {
        udph = udp_hdr(skb);
        dst = skb_dst(skb);

        if (dst && dst->xfrm) {
            pr_info("UDP Packet received and will be encrypted as ESP: Src IP %pI4:%d Dst IP %pI4:%d\n",
                &iph->saddr, ntohs(udph->source),
                &iph->daddr, ntohs(udph->dest));

            mtu = ip_skb_dst_mtu(state->sk, skb);
            /* Check if the packet is large and needs fragmentation */
            if (skb->len > mtu) {
                pr_info("Packet needs to fragmentation\n");
                err = ip_do_fragment(state->net, state->sk, skb, dst->output);
                if (err) {
                    pr_info("Failed to process packet fragmentation\n");
                    return NF_DROP;
                }
		/* Packet has been forwarded for fragmentation processing */
                return NF_STOLEN;
            }
        }
    }
    return NF_ACCEPT; /* Accept the packet */
}

/* Functions for reading and writing the flag value in /sys */
static ssize_t fragment_xfrm_show(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  char *buf)
{
    return sprintf(buf, "%d\n", do_fragment_xfrm);
}

static ssize_t fragment_xfrm_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
    sscanf(buf, "%du", &do_fragment_xfrm);
    return count;
}

/* Define attributes for /sys */
static struct kobj_attribute fragment_xfrm_attribute =
    __ATTR(do_fragment_xfrm, 0660, fragment_xfrm_show, fragment_xfrm_store);

/* Define the kobject */
static struct kobject *frag_kobj;

static int __init init_nf_module(void)
{
    int err = 0;

    /* Create the kobject */
    frag_kobj = kobject_create_and_add("xfrm_fragmentation", kernel_kobj);
    if (!frag_kobj)
        return -ENOMEM;

    /* Create the attribute in the kobject */
    err = sysfs_create_file(frag_kobj, &fragment_xfrm_attribute.attr);
    if (err) {
        kobject_put(frag_kobj);
        pr_info("Failed to create file in /sys/kernel/\n");
        return err;
    }

    /* Fill in the nf_hook_ops structure */
    nfho.hook = do_xfrm_fragmentation;
    nfho.hooknum = NF_INET_LOCAL_OUT;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    /* Register the hook */
    nf_register_net_hook(&init_net, &nfho);

    pr_info("Module initialized\n");
    return 0;
}

static void __exit cleanup_nf_module(void)
{
    /* Unregister the hook */
    nf_unregister_net_hook(&init_net, &nfho);

    /* Remove the attribute from /sys */
    kobject_put(frag_kobj);

    pr_info("Module exited\n");
}

module_init(init_nf_module);
module_exit(cleanup_nf_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Medvedev Evgenii, emedv.42@gmail.com");
MODULE_DESCRIPTION("UDP packet fragmentation for IPSec before encryption");