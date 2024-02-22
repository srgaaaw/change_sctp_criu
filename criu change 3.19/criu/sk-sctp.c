#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <sched.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/sctp.h>


#include "../soccr/sctp_soccr.h"

#include "common/config.h"
#include "cr_options.h"
#include "util.h"
#include "common/list.h"
#include "log.h"
#include "files.h"
#include "sockets.h"
#include "sk-inet.h"
#include "netfilter.h"
#include "image.h"
#include "namespaces.h"
#include "xmalloc.h"
#include "kerndat.h"
#include "restorer.h"
#include "rst-malloc.h"

#include "protobuf.h"
#include "images/sctp-stream.pb-c.h"

#undef  LOG_PREFIX
#define LOG_PREFIX "sctp: "


static LIST_HEAD(cpt_sctp_repair_sockets);
static LIST_HEAD(rst_sctp_repair_sockets);

static int sctp_repair_established(int fd, struct inet_sk_desc *sk, char repair_check)
{
	int ret;
	struct libsoccr_sctp_sk *socr;

	/* Priya: Confirm the repair condition check
	if(repair_check == false) {

		socr = libsoccr_sctp_pause(sk->rfd, repair_check);
		if (!socr)
			return -1;
		sk->priv = socr;
		return 0;
	}*/

	pr_info("\tTurning repair on for socket %x\n", sk->sd.ino);
	/*
	 * Keep the socket open in criu till the very end. In
	 * case we close this fd after one task fd dumping and
	 * fail we'll have to turn repair mode off
	 */
	sk->rfd = dup(fd);
	if (sk->rfd < 0) {
		pr_perror("Can't save socket fd for repair");
		goto err1;
	}

	if (!(root_ns_mask & CLONE_NEWNET)) {
		ret = nf_lock_connection(sk);
		if (ret < 0)
			goto err2;
	}

	socr = libsoccr_sctp_pause(sk->rfd, repair_check);
	if (!socr)
		goto err3;

	sk->priv = socr;
	list_add_tail(&sk->rlist, &cpt_sctp_repair_sockets);
	return 0;

err3:
	if (!(root_ns_mask & CLONE_NEWNET))
		nf_unlock_connection(sk);
err2:
	close(sk->rfd);
err1:
	return -1;
}

void sctp_locked_conn_add(struct inet_sk_info *ii)
{
	list_add_tail(&ii->rlist, &rst_sctp_repair_sockets);
	ii->sk_fd = -1;
}

static void sctp_unlock_one(struct inet_sk_desc *sk)
{
	int ret;

	list_del(&sk->rlist);

	if (!(root_ns_mask & CLONE_NEWNET)) {
		ret = nf_unlock_connection(sk);
		if (ret < 0)
			pr_perror("Failed to unlock SCTP connection");
	}

	libsoccr_sctp_resume(sk->priv);
	sk->priv = NULL;

	/*
	 * sctp_repair_off modifies SO_REUSEADDR so
	 * don't forget to restore original value.
	 */
	restore_opt(sk->rfd, SOL_SOCKET, SO_REUSEADDR, &sk->cpt_reuseaddr);

	close(sk->rfd);
}

void cpt_unlock_sctp_connections(void)
{
	struct inet_sk_desc *sk, *n;

	list_for_each_entry_safe(sk, n, &cpt_sctp_repair_sockets, rlist)
		sctp_unlock_one(sk);
}

static int dump_sctp_conn_state(struct inet_sk_desc *sk)
{

	struct libsoccr_sctp_sk *socr = sk->priv;
	int ret, aux;
	struct cr_img *img;
	SctpStreamEntry sse = SCTP_STREAM_ENTRY__INIT;
	//char *buf;
	struct libsoccr_sctp_sk_data data;

	if (sk->dst_port == 0) {

		/* the socket is in listen mode
		get the initial sctp configuration settings alone */
		ret = libsoccr_sctp_initconfig(socr, &data, sizeof(data));
		if (ret < 0) {
			pr_err("libsoccr_save() failed with %d\n", ret);
			goto err_r;
		}
		if (ret != sizeof(data)) {
			pr_err("This libsocr is not supported (%d vs %d)\n",
					ret, (int)sizeof(data));
			goto err_r;
		}

		sse.io_event       = data.io_event;
		sse.ass_event      = data.ass_event;
		sse.shut_event     = data.shut_event;
		sse.num_ostreams   = data.num_ostreams;
		sse.max_instreams  = data.max_instreams;
		sse.max_attempts   = data.max_attempts;
		sse.max_init_timeo = data.max_init_timeo;

	}
	else {

		ret = libsoccr_sctp_save(socr, &data, sizeof(data));
		if (ret < 0) {
			pr_err("libsoccr_save() failed with %d\n", ret);
			goto err_r;
		}
		if (ret != sizeof(data)) {
			pr_err("This libsocr is not supported (%d vs %d)\n",
					ret, (int)sizeof(data));
			goto err_r;
		}

		sse.io_event       = data.io_event;
		sse.ass_event      = data.ass_event;
		sse.shut_event     = data.shut_event;
		sse.num_ostreams   = data.num_ostreams;
		sse.max_instreams  = data.max_instreams;
		sse.max_attempts   = data.max_attempts;
		sse.max_init_timeo = data.max_init_timeo;

		sk->state = data.state;

		sse.inq_len = data.inq_len;
		sse.inq_seq = data.inq_seq;
		sse.outq_len = data.outq_len;
		sse.outq_seq = data.outq_seq;
		sse.unsq_len = data.unsq_len;
		sse.has_unsq_len = true;
		sse.mss_clamp = data.mss_clamp;
		sse.opt_mask = data.opt_mask;

		if (sse.opt_mask & TCPI_OPT_WSCALE) {
			sse.snd_wscale = data.snd_wscale;
			sse.rcv_wscale = data.rcv_wscale;
			sse.has_rcv_wscale = true;
		}
		if (sse.opt_mask & TCPI_OPT_TIMESTAMPS) {
			sse.timestamp = data.timestamp;
			sse.has_timestamp = true;
		}

		/*if (data.flags & SOCCR_FLAGS_WINDOW) {
			sse.has_snd_wl1		= true;
			sse.has_snd_wnd		= true;
			sse.has_max_window	= true;
			sse.has_rcv_wnd		= true;
			sse.has_rcv_wup		= true;
			sse.snd_wl1		= data.snd_wl1;
			sse.snd_wnd		= data.snd_wnd;
			sse.max_window		= data.max_window;
			sse.rcv_wnd		= data.rcv_wnd;
			sse.rcv_wup		= data.rcv_wup;
		}*/

		/*
		 * SCTP socket options
		 */

		if (dump_opt(sk->rfd, SOL_SCTP, SCTP_NODELAY, &aux))
			goto err_opt;

		if (aux) {
			sse.has_nodelay = true;
			sse.nodelay = true;
		}
	}

	/*
	 * Push the stuff to image
	 */


	img = open_image(CR_FD_SCTP_STREAM, O_DUMP, sk->sd.ino);
	if (!img)
		goto err_img;

	ret = pb_write_one(img, &sse, PB_SCTP_STREAM);
	if (ret < 0)
		goto err_iw;

	/* Priya - Not needed now
	buf = libsoccr_sctp_get_queue_bytes(socr, TCP_RECV_QUEUE, SOCCR_MEM_EXCL);
	if (buf) {
		ret = write_img_buf(img, buf, sse.inq_len);
		if (ret < 0)
			goto err_iw;

		xfree(buf);
	}

	buf = libsoccr_sctp_get_queue_bytes(socr, TCP_SEND_QUEUE, SOCCR_MEM_EXCL);
	if (buf) {
		ret = write_img_buf(img, buf, sse.outq_len);
		if (ret < 0)
			goto err_iw;

		xfree(buf);
	} */

	pr_info("Done\n");
err_iw:
	close_image(img);
err_img:
err_opt:
err_r:
	return ret;
}




int dump_one_sctp(int fd, struct inet_sk_desc *sk)
{
	char repair_check = true;
	char src_addr[INET_ADDR_LEN] = "<unknown>";
	char dest_addr[INET_ADDR_LEN] = "<unknown>";

	/* Priya: Need some sctp parameters in listen mode. No kernel changes for sctp */
		if (sk->dst_port == 0)
			repair_check = false;

	if (inet_ntop(sk->sd.family, (void *)sk->src_addr, src_addr,
			      INET_ADDR_LEN) == NULL) {
			pr_perror("Failed to translate address");
	}

	if (inet_ntop(sk->sd.family, (void *)sk->dst_addr, dest_addr,
				      INET_ADDR_LEN) == NULL) {
				pr_perror("Failed to translate address");
	}
	pr_debug("Dumping SCTP connection for fd %d src:dest port %d :%d and src:dest addr %s:%s \n", fd, sk->src_port,
						sk->dst_port,src_addr, dest_addr);


	if (sctp_repair_established(fd, sk, repair_check))
		return -1;

	if (dump_sctp_conn_state(sk))
		return -1;

	/*
	 * Socket is left in repair mode, so that at the end it's just
	 * closed and the connection is silently terminated
	 */
	return 0;
}

void rst_unlock_sctp_connections(void)
{
	struct inet_sk_info *ii;

	/* Network will be unlocked by network-unlock scripts */
	if (root_ns_mask & CLONE_NEWNET)
		return;

	list_for_each_entry(ii, &rst_sctp_repair_sockets, rlist)
		nf_unlock_connection_info(ii);
}

/* Priya: temp function not needed after validation */
//#ifdef union_sctp_add_needed
#define PB_ALEN_INET	1
#define PB_ALEN_INET6	4
static int restore_sctp_sockaddr(union libsoccr_sctp_addr *sa,
		int family, u32 pb_port, u32 *pb_addr, u32 ifindex)
{
	char src_addr[INET_ADDR_LEN] = "<unknown>";
	BUILD_BUG_ON(sizeof(sa->v4.sin_addr.s_addr) > PB_ALEN_INET * sizeof(u32));
	BUILD_BUG_ON(sizeof(sa->v6.sin6_addr.s6_addr) > PB_ALEN_INET6 * sizeof(u32));

	memzero(sa, sizeof(*sa));

	if (family == AF_INET) {
		sa->v4.sin_family = AF_INET;
		sa->v4.sin_port = htons(pb_port);
		memcpy(&sa->v4.sin_addr.s_addr, pb_addr, sizeof(sa->v4.sin_addr.s_addr));


		if (inet_ntop(family, pb_addr, src_addr,
				  INET_ADDR_LEN) == NULL) {
			pr_debug("Failed to translate address");
		}

		pr_debug("\t SCTP family %d  port %d src_addr %s\n",
			family,pb_port,src_addr);
		return sizeof(sa->v4);
	}

	if (family == AF_INET6) {
		sa->v6.sin6_family = AF_INET6;
		sa->v6.sin6_port = htons(pb_port);
		memcpy(sa->v6.sin6_addr.s6_addr, pb_addr, sizeof(sa->v6.sin6_addr.s6_addr));

		if (inet_ntop(family, pb_addr, src_addr, INET_ADDR_LEN) == NULL) {
				pr_debug("Failed to translate address");
			}

		pr_debug("\t SCTP family %d  port %d src_addr %s\n", family,pb_port,src_addr);

		/* Here although the struct member is called scope_id, the
		 * kernel really wants ifindex. See
		 * /net/ipv6/af_inet6.c:inet6_bind for details.
		 */
		sa->v6.sin6_scope_id = ifindex;
		return sizeof(sa->v6);
	}

	BUG();
	return -1;
}
//#endif

static int restore_sctp_conn_state(int sk, struct libsoccr_sctp_sk *socr, struct inet_sk_info *ii)
{
	int aux;
	struct cr_img *img;
	SctpStreamEntry *sse;
	struct libsoccr_sctp_sk_data data = {};
	union libsoccr_sctp_addr sa_src, sa_dst;

	pr_info("Restoring SCTP connection id %x ino %x\n", ii->ie->id, ii->ie->ino);

	img = open_image(CR_FD_SCTP_STREAM, O_RSTR, ii->ie->ino);
	if (!img)
		goto err;

	if (pb_read_one(img, &sse, PB_SCTP_STREAM) < 0)
		goto err_c;

	/* Priya: Confirm the need for it
		if (!tse->has_unsq_len) {
			pr_err("No unsq len in the image\n");
			goto err_c;
	}*/

	if(ii->ie->dst_port == 0) {
		/* Get the SCTP INIT STREAM and SCTP_EVENT information alone
		since the socket is in listen mode */
		data.state          = ii->ie->state;
		data.io_event       = sse->io_event;
		data.ass_event      = sse->ass_event;
		data.shut_event     = sse->shut_event;
		data.num_ostreams   = sse->num_ostreams;
		data.max_instreams  = sse->max_instreams;
		data.max_attempts   = sse->max_attempts;
		data.max_init_timeo = sse->max_init_timeo;

		libsoccr_set_sctp_initconfig(socr, &data);
	}
	else {
		data.state          = ii->ie->state;
		data.io_event       = sse->io_event;
		data.ass_event      = sse->ass_event;
		data.shut_event     = sse->shut_event;
		data.num_ostreams   = sse->num_ostreams;
		data.max_instreams  = sse->max_instreams;
		data.max_attempts   = sse->max_attempts;
		data.max_init_timeo = sse->max_init_timeo;

		data.inq_len   = sse->inq_len;
		data.inq_seq   = sse->inq_seq;
		data.outq_len  = sse->outq_len;
		data.outq_seq  = sse->outq_seq;
		data.unsq_len  = sse->unsq_len;
		data.mss_clamp = sse->mss_clamp;
		data.opt_mask  = sse->opt_mask;

		/*if (sse->opt_mask & TCPI_OPT_WSCALE) {
			if (!tse->has_rcv_wscale) {
				pr_err("No rcv wscale in the image\n");
				goto err_c;
			}

			data.snd_wscale = tse->snd_wscale;
			data.rcv_wscale = tse->rcv_wscale;
		}
		if (tse->opt_mask & TCPI_OPT_TIMESTAMPS) {
			if (!tse->has_timestamp) {
				pr_err("No timestamp in the image\n");
				goto err_c;
			}

			data.timestamp = tse->timestamp;
		}

		if (tse->has_snd_wnd) {
			data.flags |= SOCCR_FLAGS_WINDOW;
			data.snd_wl1 = tse->snd_wl1;
			data.snd_wnd = tse->snd_wnd;
			data.max_window = tse->max_window;
			data.rcv_wnd = tse->rcv_wnd;
			data.rcv_wup = tse->rcv_wup;
		} */

		/* Priya - please do call restore_sockaddr after complete validation
		dont include soccr.h as of now to avoid tmp mistakes */
		if (restore_sctp_sockaddr(&sa_src,
					ii->ie->family, ii->ie->src_port,
					ii->ie->src_addr, 0) < 0)
			goto err_c;
		if (restore_sctp_sockaddr(&sa_dst,
					ii->ie->family, ii->ie->dst_port,
					ii->ie->dst_addr, 0) < 0)
			goto err_c;

		libsoccr_sctp_set_addr(socr, 1, &sa_src, 0);
		libsoccr_sctp_set_addr(socr, 0, &sa_dst, 0);

		/*
		 * O_NONBLOCK has to be set before libsoccr_restore(),
		 * it is required to restore syn-sent sockets.
		 */
		if (restore_prepare_socket(sk))
			goto err_c;

		/*if (read_tcp_queues(socr, &data, img))
			goto err_c;*/

		if (libsoccr_sctp_restore(socr, &data, sizeof(data)))
			goto err_c;

		if (sse->has_nodelay && sse->nodelay) {
			aux = 1;
			if (restore_opt(sk, SOL_SCTP, SCTP_NODELAY, &aux))
				goto err_c;
		}

		/*if (tse->has_cork && tse->cork) {
			aux = 1;
			if (restore_opt(sk, SOL_TCP, TCP_CORK, &aux))
				goto err_c;
		}*/
	}

	sctp_stream_entry__free_unpacked(sse, NULL);
	close_image(img);
	return 0;

err_c:
	sctp_stream_entry__free_unpacked(sse, NULL);
	close_image(img);
err:
	return -1;
}

int restore_one_sctp(int fd, struct inet_sk_info *ii)
{
	struct libsoccr_sctp_sk *sk;
	char repair_check = true;

	pr_info("Restoring SCTP connection\n");

	/* Priya: check the opts value
	if (opts.tcp_close &&
		ii->ie->state != TCP_LISTEN && ii->ie->state != TCP_CLOSE) {
		return 0;
	} */

	if(ii->ie->dst_port == 0)
		repair_check = false;

	sk = libsoccr_sctp_pause(fd,repair_check);
	if (!sk)
		return -1;

	if (restore_sctp_conn_state(fd, sk, ii)) {
		libsoccr_sctp_release(sk);
		return -1;
	}

	return 0;
}
