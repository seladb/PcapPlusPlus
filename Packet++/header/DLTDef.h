#ifndef PCAPPP_DLT_DEF
#define PCAPPP_DLT_DEF

/*
 * Due to difficulty on successfully building on WIN32 with WinPcap after
 * including the whole header file pcap/bpf.h, have to directly port these 
 * macros from pcap/bpf.h
 */

/*
 * Link-layer header type codes.
 *
 * Do *NOT* add new values to this list without asking
 * "tcpdump-workers@lists.tcpdump.org" for a value.  Otherwise, you run
 * the risk of using a value that's already being used for some other
 * purpose, and of having tools that read libpcap-format captures not
 * being able to handle captures with your new DLT_ value, with no hope
 * that they will ever be changed to do so (as that would destroy their
 * ability to read captures using that value for that other purpose).
 *
 * See
 *
 *	http://www.tcpdump.org/linktypes.html
 *
 * for detailed descriptions of some of these link-layer header types.
 */

/*
 * These are the types that are the same on all platforms, and that
 * have been defined by <net/bpf.h> for ages.
 */
#define DLT_NULL	0	/* BSD loopback encapsulation */
#define DLT_EN10MB	1	/* Ethernet (10Mb) */
#define DLT_EN3MB	2	/* Experimental Ethernet (3Mb) */
#define DLT_AX25	3	/* Amateur Radio AX.25 */
#define DLT_PRONET	4	/* Proteon ProNET Token Ring */
#define DLT_CHAOS	5	/* Chaos */
#define DLT_IEEE802	6	/* 802.5 Token Ring */
#define DLT_ARCNET	7	/* ARCNET, with BSD-style header */
#define DLT_SLIP	8	/* Serial Line IP */
#define DLT_PPP		9	/* Point-to-point Protocol */
#define DLT_FDDI	10	/* FDDI */

/*
 * These are types that are different on some platforms, and that
 * have been defined by <net/bpf.h> for ages.  We use #ifdefs to
 * detect the BSDs that define them differently from the traditional
 * libpcap <net/bpf.h>
 *
 * XXX - DLT_ATM_RFC1483 is 13 in BSD/OS, and DLT_RAW is 14 in BSD/OS,
 * but I don't know what the right #define is for BSD/OS.
 */
#define DLT_ATM_RFC1483	11	/* LLC-encapsulated ATM */

#ifdef __OpenBSD__
#define DLT_RAW		14	/* raw IP */
#else
#define DLT_RAW		12	/* raw IP */
#endif

/*
 * Given that the only OS that currently generates BSD/OS SLIP or PPP
 * is, well, BSD/OS, arguably everybody should have chosen its values
 * for DLT_SLIP_BSDOS and DLT_PPP_BSDOS, which are 15 and 16, but they
 * didn't.  So it goes.
 */
#if defined(__NetBSD__) || defined(__FreeBSD__)
#ifndef DLT_SLIP_BSDOS
#define DLT_SLIP_BSDOS	13	/* BSD/OS Serial Line IP */
#define DLT_PPP_BSDOS	14	/* BSD/OS Point-to-point Protocol */
#endif
#else
#define DLT_SLIP_BSDOS	15	/* BSD/OS Serial Line IP */
#define DLT_PPP_BSDOS	16	/* BSD/OS Point-to-point Protocol */
#endif

/*
 * 17 was used for DLT_PFLOG in OpenBSD; it no longer is.
 *
 * It was DLT_LANE8023 in SuSE 6.3, so we defined LINKTYPE_PFLOG
 * as 117 so that pflog captures would use a link-layer header type
 * value that didn't collide with any other values.  On all
 * platforms other than OpenBSD, we defined DLT_PFLOG as 117,
 * and we mapped between LINKTYPE_PFLOG and DLT_PFLOG.
 *
 * OpenBSD eventually switched to using 117 for DLT_PFLOG as well.
 *
 * Don't use 17 for anything else.
 */

/*
 * 18 is used for DLT_PFSYNC in OpenBSD, NetBSD, DragonFly BSD and
 * Mac OS X; don't use it for anything else.  (FreeBSD uses 121,
 * which collides with DLT_HHDLC, even though it doesn't use 18
 * for anything and doesn't appear to have ever used it for anything.)
 *
 * We define it as 18 on those platforms; it is, unfortunately, used
 * for DLT_CIP in Suse 6.3, so we don't define it as DLT_PFSYNC
 * in general.  As the packet format for it, like that for
 * DLT_PFLOG, is not only OS-dependent but OS-version-dependent,
 * we don't support printing it in tcpdump except on OSes that
 * have the relevant header files, so it's not that useful on
 * other platforms.
 */
#if defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__) || defined(__APPLE__)
#define DLT_PFSYNC	18
#endif

#define DLT_ATM_CLIP	19	/* Linux Classical-IP over ATM */

/*
 * Apparently Redback uses this for its SmartEdge 400/800.  I hope
 * nobody else decided to use it, too.
 */
#define DLT_REDBACK_SMARTEDGE	32

/*
 * These values are defined by NetBSD; other platforms should refrain from
 * using them for other purposes, so that NetBSD savefiles with link
 * types of 50 or 51 can be read as this type on all platforms.
 */
#define DLT_PPP_SERIAL	50	/* PPP over serial with HDLC encapsulation */
#define DLT_PPP_ETHER	51	/* PPP over Ethernet */

/*
 * The Axent Raptor firewall - now the Symantec Enterprise Firewall - uses
 * a link-layer type of 99 for the tcpdump it supplies.  The link-layer
 * header has 6 bytes of unknown data, something that appears to be an
 * Ethernet type, and 36 bytes that appear to be 0 in at least one capture
 * I've seen.
 */
#define DLT_SYMANTEC_FIREWALL	99

/*
 * Values between 100 and 103 are used in capture file headers as
 * link-layer header type LINKTYPE_ values corresponding to DLT_ types
 * that differ between platforms; don't use those values for new DLT_
 * new types.
 */


#endif/*  PCAPPP_DLT_DEF */

