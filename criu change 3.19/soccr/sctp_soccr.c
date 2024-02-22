#include <errno.h>
#include <libnet.h>
#include <linux/sockios.h>
#include <linux/types.h>
#include <netinet/sctp.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include "sctp_soccr.h"



#define SCTP_REPAIR 38
#define SCTP_LISTEN 10

struct libsoccr_sctp_sk {
	int fd;
	unsigned flags;
	char *recv_queue;
	char *send_queue;
	union libsoccr_sctp_addr *src_addr;
	union libsoccr_sctp_addr *dst_addr;
};


static void (*log)(unsigned int loglevel, const char *format, ...)
	__attribute__ ((__format__ (__printf__, 2, 3)));
static unsigned int log_level = 0;

void libsoccr_sctp_set_log(unsigned int level, void (*fn)(unsigned int level, const char *fmt, ...))
{
	log_level = level;
	log = fn;
}

#define loge(msg, ...) do { if (log && (log_level >= SOCCR_SCTP_LOG_ERR)) log(SOCCR_SCTP_LOG_ERR, "Error (%s:%d): " msg, __FILE__, __LINE__, ##__VA_ARGS__); } while (0)
#define logerr(msg, ...) loge(msg ": %s\n", ##__VA_ARGS__, strerror(errno))
#define logd(msg, ...) do { if (log && (log_level >= SOCCR_SCTP_LOG_DBG)) log(SOCCR_SCTP_LOG_DBG, "Debug: " msg, ##__VA_ARGS__); } while (0)

#define SCTP_REPAIR_SUPPORTED 1

#ifdef SCTP_REPAIR_SUPPORTED
static int sctp_repair_on(int fd)
{
	int ret, aux = 1;

	ret = setsockopt(fd, SOL_SCTP, SCTP_REPAIR, &aux, sizeof(aux));
	if (ret < 0)
		logerr("Can't turn SCTP repair mode ON");

	/* Priya for testing the kernel
	socklen_t olen = sizeof(aux);

	ret = getsockopt(fd, SOL_SCTP, SCTP_REPAIR, &aux, &olen);
	if (ret < 0)
		logerr("Can't read SCTP repair mode ON");
	else
		logerr("SCTP mode: %d\n",aux);*/

	return ret;
}

static int sctp_repair_off(int fd)
{
	int aux = 0, ret;

	ret = setsockopt(fd, SOL_SCTP, SCTP_REPAIR, &aux, sizeof(aux));
	if (ret < 0)
		logerr("Failed to turn off repair mode on socket");

	return ret;
}
#endif





struct libsoccr_sctp_sk *libsoccr_sctp_pause(int fd, char repair_check)
{
	struct libsoccr_sctp_sk *ret;

	ret = malloc(sizeof(*ret));
	if (!ret) {
		loge("Unable to allocate memory\n");
		return NULL;
	}

	#ifdef SCTP_REPAIR_SUPPORTED
	if(repair_check == true) {
		if (sctp_repair_on(fd) < 0) {
			free(ret);
			return NULL;
		}
	}
	#endif

	ret->flags = 0;
	ret->recv_queue = NULL;
	ret->send_queue = NULL;
	ret->src_addr = NULL;
	ret->dst_addr = NULL;
	ret->fd = fd;
	return ret;
}

/*struct soccr_sctp_status {
	uint32_t sstat_assoc_id;
	int32_t  sstat_state;
	uint32_t sstat_rwnd;
	uint16_t sstat_unackdata;
	uint16_t sstat_penddata;
	uint16_t sstat_instrms;
	uint16_t sstat_outstrms;
	uint32_t sstat_fragmentation_point;
};*/

/* Restore a fin packet in a send queue first */
/* Priya - Come up with the SCTP Shutdown state
#define SNDQ_FIRST_FIN	(TCPF_FIN_WAIT1 | TCPF_FIN_WAIT2 | TCPF_CLOSING)
// Restore fin in a send queue after restoring fi in the receive queue.
#define SNDQ_SECOND_FIN (TCPF_LAST_ACK | TCPF_CLOSE)
#define SNDQ_FIN_ACKED	(TCPF_FIN_WAIT2 | TCPF_CLOSE)

#define RCVQ_FIRST_FIN	(TCPF_CLOSE_WAIT | TCPF_LAST_ACK | TCPF_CLOSE)
#define RCVQ_SECOND_FIN (TCPF_CLOSING)
#define RCVQ_FIN_ACKED	(TCPF_CLOSE) */

static int refresh_sctp_sk(struct libsoccr_sctp_sk *sk,
			struct libsoccr_sctp_sk_data *data, struct sctp_status *ss)
{

	socklen_t olen = sizeof(*ss);

	if (getsockopt(sk->fd, SOL_SCTP, SCTP_STATUS, ss, &olen) || olen != sizeof(*ss)) {
		logerr("Failed to obtain SCTP_STATUS");
		return -1;
	}

	logd("Priya: SCTP Status %d\n",ss->sstat_state);
#ifdef PRIYA_CHANGE_SCTP_STATUS
	switch (ss->sstat_state) {
	case SCTP_ESTABLISHED:
		data->state = SCTP_STATE_ESTABLISHED;
		break;
	case SCTP_SHUTDOWN_ACK_SENT:
		data->state = SCTP_STATE_SHUTDOWN_ACK_SENT;
		break;
	case SCTP_SHUTDOWN_RECEIVED:
		data->state = SCTP_STATE_SHUTDOWN_RECEIVED;
		break;
	case SCTP_SHUTDOWN_PENDING:
		data->state = SCTP_STATE_SHUTDOWN_PENDING;
		break;
	case SCTP_SHUTDOWN_SENT:
		data->state = SCTP_STATE_SHUTDOWN_SENT;
		break;
	case SCTP_COOKIE_WAIT:
		data->state = SCTP_STATE_COOKIE_WAIT;
		break;
	case SCTP_COOKIE_ECHOED:
		data->state = SCTP_STATE_COOKIE_ECHOED;
		break;
	case SCTP_CLOSED:
		data->state = SCTP_STATE_CLOSED;
		break;
	default:
		loge("Unknown state %d\n", ss->sstat_state);
		return -1;
	}
#endif

	switch (ss->sstat_state) {
		case SCTP_ESTABLISHED:
		case SCTP_SHUTDOWN_ACK_SENT:
		case SCTP_SHUTDOWN_RECEIVED:
		case SCTP_SHUTDOWN_PENDING:
		case SCTP_SHUTDOWN_SENT:
		case SCTP_COOKIE_WAIT:
		case SCTP_COOKIE_ECHOED:
		case SCTP_CLOSED:
			break;
		default:
			loge("Unknown state %d\n", ss->sstat_state);
			return -1;
	}

	data->state = ss->sstat_state - 1;


	#ifdef QUEUE_NOT_DEFINED_SCTP
	int size;

	if (ioctl(sk->fd, SIOCOUTQ, &size) == -1) {
		logerr("Unable to get size of snd queue");
		return -1;
	}

	data->outq_len = size;

	if (ioctl(sk->fd, SIOCOUTQNSD, &size) == -1) {
		logerr("Unable to get size of unsent data");
		return -1;
	}

	data->unsq_len = size;

	if (data->state == SCTP_CLOSED) {
		/* A connection could be reseted. In thise case a sent queue
		 * may contain some data. A user can't read this data, so let's
		 * ignore them. Otherwise we will need to add a logic whether
		 * the send queue contains a fin packet or not and decide whether
		 * a fin or reset packet has to be sent to restore a state
		 */

		data->unsq_len = 0;
		data->outq_len = 0;
	}

	/* Don't account the fin packet. It doesn't countain real data. */
	/*Priya - To check on the data content for shutdown
	if ((1 << data->state) & (SNDQ_FIRST_FIN | SNDQ_SECOND_FIN)) {
		if (data->outq_len)
			data->outq_len--;
		data->unsq_len = data->unsq_len ? data->unsq_len - 1 : 0;
	}*/

	if (ioctl(sk->fd, SIOCINQ, &size) == -1) {
		logerr("Unable to get size of recv queue");
		return -1;
	}

	data->inq_len = size;
	#endif

	return 0;
}

static int get_sctp_initconfig(struct libsoccr_sctp_sk *sk,
		struct libsoccr_sctp_sk_data *data)
{
	int ret;
	socklen_t auxl;
	//int val;

	struct sctp_initmsg  init = {0};
	struct sctp_event_subscribe  event = {0};

	auxl = sizeof(struct sctp_initmsg);
	ret = getsockopt(sk->fd, SOL_SCTP, SCTP_INITMSG, &init, &auxl);
	if (ret < 0)
		goto err_sopt;

	data->num_ostreams  = (uint16_t)init.sinit_num_ostreams;
	data->max_instreams = (uint16_t)init.sinit_max_instreams;
	data->max_attempts  = (uint16_t)init.sinit_max_attempts;
	data->max_init_timeo = (uint16_t)init.sinit_max_init_timeo;


	auxl = sizeof(struct sctp_event_subscribe);
	ret = getsockopt(sk->fd, SOL_SCTP, SCTP_EVENTS, &event, &auxl);
	if (ret < 0)
		goto err_sopt;

	logd("cp sctp num_ostreams %d instreams %d attempts %d timeout %d timeout %d\n",data->num_ostreams,
				data->max_instreams,data->max_attempts,data->max_init_timeo,init.sinit_max_init_timeo);

	data->io_event  = event.sctp_data_io_event;
	data->ass_event = event.sctp_association_event;
	data->shut_event  = event.sctp_shutdown_event;

	loge("cp sctp io_event %d ass_event %d shut_event %d \n",data->io_event, data->ass_event,data->shut_event);
	logd("cp sctp io_event %d ass_event %d shut_event %d \n",data->io_event, data->ass_event,data->shut_event);


	return 0;

err_sopt:
	logerr("\tsockopt failed");
	return -1;
}


static int get_sctp_stream_options(struct libsoccr_sctp_sk *sk,
		struct libsoccr_sctp_sk_data *data)
{
	int ret;
	socklen_t auxl;
	//int val;

	auxl = sizeof(data->mss_clamp);
	ret = getsockopt(sk->fd, SOL_SCTP, SCTP_MAXSEG, &data->mss_clamp, &auxl);
	if (ret < 0)
		goto err_sopt;

	/* Priya - SCTP options not given
	data->opt_mask = ti->tcpi_options;
	if (ti->tcpi_options & TCPI_OPT_WSCALE) {
		data->snd_wscale = ti->tcpi_snd_wscale;
		data->rcv_wscale = ti->tcpi_rcv_wscale;
	}

	if (ti->tcpi_options & TCPI_OPT_TIMESTAMPS) {
		auxl = sizeof(val);
		ret = getsockopt(sk->fd, SOL_TCP, TCP_TIMESTAMP, &val, &auxl);
		if (ret < 0)
			goto err_sopt;

		data->timestamp = val;
	} */

	return 0;

err_sopt:
	logerr("\tsockopt failed");
	return -1;
}


/*
 * This is how much data we've had in the initial libsoccr
 */
#define SOCR_DATA_MIN_SIZE	(17 * sizeof(__u32))

int libsoccr_sctp_initconfig(struct libsoccr_sctp_sk *sk, struct libsoccr_sctp_sk_data *data, unsigned data_size)
{


	if (!data || data_size < SOCR_DATA_MIN_SIZE) {
		loge("Invalid input parameters\n");
		return -1;
	}

	memset(data, 0, data_size);

	if (get_sctp_initconfig(sk, data))
		return -2;

	return sizeof(struct libsoccr_sctp_sk_data);
}


int libsoccr_sctp_save(struct libsoccr_sctp_sk *sk, struct libsoccr_sctp_sk_data *data, unsigned data_size)
{
	struct sctp_status ss;

	if (!data || data_size < SOCR_DATA_MIN_SIZE) {
		loge("Invalid input parameters\n");
		return -1;
	}

	memset(data, 0, data_size);
	memset(&ss, 0, sizeof(struct sctp_status));

	if (get_sctp_initconfig(sk, data))
		return -2;

	if (refresh_sctp_sk(sk, data, &ss))
		return -3;


	if (get_sctp_stream_options(sk, data))
		return -4;

	/* Priya - Not sctp property
	if (get_window(sk, data))
		return -4; */

	//sk->flags |= SK_FLAG_FREE_SQ | SK_FLAG_FREE_RQ;

	/* Priya - Need to explore
	if (get_queue(sk->fd, TCP_RECV_QUEUE, &data->inq_seq, data->inq_len, &sk->recv_queue))
		return -5;

	if (get_queue(sk->fd, TCP_SEND_QUEUE, &data->outq_seq, data->outq_len, &sk->send_queue))
		return -6; */

	return sizeof(struct libsoccr_sctp_sk_data);
}

void libsoccr_sctp_resume(struct libsoccr_sctp_sk *sk)
{
	#ifdef SCTP_REPAIR_SUPPORTED
	sctp_repair_off(sk->fd);
	#endif
	libsoccr_sctp_release(sk);
}

void libsoccr_sctp_release(struct libsoccr_sctp_sk *sk)
{
	/*if (sk->flags & SK_FLAG_FREE_RQ)
		free(sk->recv_queue);
	if (sk->flags & SK_FLAG_FREE_SQ)
		free(sk->send_queue);
	if (sk->flags & SK_FLAG_FREE_SA)
		free(sk->src_addr);
	if (sk->flags & SK_FLAG_FREE_DA)
		free(sk->dst_addr);*/
	free(sk);
}
#define SOCCR_MEM_EXCL		0x1
#define SET_SA_FLAGS	(SOCCR_MEM_EXCL)
int libsoccr_sctp_set_addr(struct libsoccr_sctp_sk *sk, int self, union libsoccr_sctp_addr *addr, unsigned flags)
{
	if (flags & ~SET_SA_FLAGS)
		return -1;

	if (self) {
		sk->src_addr = addr;
		/* Priya: Confirm it
			if (flags & SOCCR_MEM_EXCL)
			sk->flags |= SK_FLAG_FREE_SA; */
	} else {
		sk->dst_addr = addr;
		/* Priya: Confirm it
		if (flags & SOCCR_MEM_EXCL)
			sk->flags |= SK_FLAG_FREE_DA; */
	}

	return 0;
}

int libsoccr_set_sctp_initconfig(struct libsoccr_sctp_sk *sk, struct libsoccr_sctp_sk_data *data)
{

	struct sctp_initmsg  init = {0};
	struct sctp_event_subscribe  event = {0};

	memset ((void *)&init, 0, sizeof (struct sctp_initmsg));
	memset ((void *)&event, 0, sizeof (struct sctp_event_subscribe));

	/*
	* Get the number of streams
	*/
	init.sinit_num_ostreams   = (uint16_t)data->num_ostreams;
	init.sinit_max_instreams  = (uint16_t)data->max_instreams;
	init.sinit_max_attempts   = (uint16_t)data->max_attempts;
	init.sinit_max_init_timeo = (uint16_t)data->max_init_timeo;

	if (setsockopt (sk->fd, IPPROTO_SCTP, SCTP_INITMSG, &init, sizeof (struct sctp_initmsg)) < 0) {
		logerr("SCTP stream set failure\n");
		return -1;
	}

	loge("r sctp num_ostreams %d instreams %d attempts %d timeout %d\n",data->num_ostreams, data->max_instreams,data->max_attempts,data->max_init_timeo);
	logd("r sctp num_ostreams %d instreams %d attempts %d timeout %d\n",data->num_ostreams, data->max_instreams,data->max_attempts,data->max_init_timeo);

	event.sctp_association_event = data->io_event;
	event.sctp_shutdown_event    = data->ass_event;
	event.sctp_data_io_event     = data->shut_event;

	loge("r sctp io_event %d ass_event %d shut_event %d \n",data->io_event, data->ass_event,data->shut_event);
	logd("r sctp io_event %d ass_event %d shut_event %d \n",data->io_event, data->ass_event,data->shut_event);

	if (setsockopt (sk->fd, IPPROTO_SCTP, SCTP_EVENTS, &event, sizeof (struct sctp_event_subscribe)) < 0) {
		logerr("SCTP event set failure\n");
		return -2;
  }

  return 0;

}

static int libsoccr_set_sctp_sk_data_noq(struct libsoccr_sctp_sk *sk,
		struct libsoccr_sctp_sk_data *data, unsigned data_size)
{
	//struct tcp_repair_opt opts[4];
	int addr_size; //, mstate;
	//int onr = 0;
	//__u32 seq;

	if (!data || data_size < SOCR_DATA_MIN_SIZE) {
		loge("Invalid input parameters\n");
		return -1;
	}

	if (!sk->dst_addr || !sk->src_addr) {
		loge("Destination or/and source addresses aren't set\n");
		return -1;
	}

	//mstate = 1 << data->state;

	if (data->state == SCTP_LISTEN) {
		loge("Unable to handle SCTP listen sockets \n");
		return -1;
	}

	if (sk->src_addr->sa.sa_family == AF_INET)
		addr_size = sizeof(sk->src_addr->v4);
	else{
		int yes = 1;
		addr_size = sizeof(sk->src_addr->v6);

		if (setsockopt(sk->fd, SOL_IP, IP_FREEBIND, &yes, sizeof(yes)))
			return -1;
	}


	if (bind(sk->fd, &sk->src_addr->sa, addr_size)) {
		logerr("Can't bind inet socket back");
		return -1;
	}

	libsoccr_set_sctp_initconfig(sk, data);

	/*if (mstate & (RCVQ_FIRST_FIN | RCVQ_SECOND_FIN))
		data->inq_seq--;

	// outq_seq is adjusted due to not accointing the fin packet
	if (mstate & (SNDQ_FIRST_FIN | SNDQ_SECOND_FIN))
		data->outq_seq--;

	if (set_queue_seq(sk, TCP_RECV_QUEUE,
				data->inq_seq - data->inq_len))
		return -2;*/

	//seq = data->outq_seq - data->outq_len;
	/*if (data->state == TCP_SYN_SENT)
		seq--;

	if (set_queue_seq(sk, TCP_SEND_QUEUE, seq))
		return -3;

	if (sk->dst_addr->sa.sa_family == AF_INET)
		addr_size = sizeof(sk->dst_addr->v4);
	else
		addr_size = sizeof(sk->dst_addr->v6);

	if (data->state == TCP_SYN_SENT && tcp_repair_off(sk->fd))
		return -1;*/

	if (connect(sk->fd, &sk->dst_addr->sa, addr_size) == -1 &&
						errno != EINPROGRESS) {
		logerr("Can't connect inet socket back");
		return -1;
	}

	/*if (data->state == TCP_SYN_SENT && tcp_repair_on(sk->fd))
		return -1;*/

	logd("\tRestoring SCTP options\n");

	/*if (data->opt_mask & TCPI_OPT_SACK) {
		logd("\t\tWill turn SAK on\n");
		opts[onr].opt_code = TCPOPT_SACK_PERM;
		opts[onr].opt_val = 0;
		onr++;
	}

	if (data->opt_mask & TCPI_OPT_WSCALE) {
		logd("\t\tWill set snd_wscale to %u\n", data->snd_wscale);
		logd("\t\tWill set rcv_wscale to %u\n", data->rcv_wscale);
		opts[onr].opt_code = TCPOPT_WINDOW;
		opts[onr].opt_val = data->snd_wscale + (data->rcv_wscale << 16);
		onr++;
	}

	if (data->opt_mask & TCPI_OPT_TIMESTAMPS) {
		logd("\t\tWill turn timestamps on\n");
		opts[onr].opt_code = TCPOPT_TIMESTAMP;
		opts[onr].opt_val = 0;
		onr++;
	}

	logd("Will set mss clamp to %u\n", data->mss_clamp);
	opts[onr].opt_code = TCPOPT_MAXSEG;
	opts[onr].opt_val = data->mss_clamp;
	onr++;

	if (data->state != TCP_SYN_SENT &&
	    setsockopt(sk->fd, SOL_TCP, TCP_REPAIR_OPTIONS,
				opts, onr * sizeof(struct tcp_repair_opt)) < 0) {
		logerr("Can't repair options");
		return -2;
	}

	if (data->opt_mask & TCPI_OPT_TIMESTAMPS) {
		if (setsockopt(sk->fd, SOL_TCP, TCP_TIMESTAMP,
				&data->timestamp, sizeof(data->timestamp)) < 0) {
			logerr("Can't set timestamp");
			return -3;
		}
	}*/

	return 0;
}

int libsoccr_sctp_restore(struct libsoccr_sctp_sk *sk,
		struct libsoccr_sctp_sk_data *data, unsigned data_size)
{
	//int mstate = 1 << data->state;

	if (libsoccr_set_sctp_sk_data_noq(sk, data, data_size))
		return -1;

	/*if (libsoccr_restore_queue(sk, data, sizeof(*data), TCP_RECV_QUEUE, sk->recv_queue))
		return -1;

	if (libsoccr_restore_queue(sk, data, sizeof(*data), TCP_SEND_QUEUE, sk->send_queue))
		return -1; */

	/* Priya: Handle the below cases with the SCTP_Repair_Option turned on
	if (data->flags & SOCCR_FLAGS_WINDOW) {
		struct tcp_repair_window wopt = {
			.snd_wl1 = data->snd_wl1,
			.snd_wnd = data->snd_wnd,
			.max_window = data->max_window,
			.rcv_wnd = data->rcv_wnd,
			.rcv_wup = data->rcv_wup,
		};

		if (mstate & (RCVQ_FIRST_FIN | RCVQ_SECOND_FIN)) {
			wopt.rcv_wup--;
			wopt.rcv_wnd++;
		}

		if (setsockopt(sk->fd, SOL_TCP, TCP_REPAIR_WINDOW, &wopt, sizeof(wopt))) {
			logerr("Unable to set window parameters");
			return -1;
		}
	} */

	/*
	 * To restore a half closed sockets, fin packets has to be restored in
	 * recv and send queues. Here shutdown() is used to restore a fin
	 * packet in the send queue and a fake fin packet is send to restore it
	 * in the recv queue.
	 */

	/*
	if (mstate & SNDQ_FIRST_FIN)
		restore_fin_in_snd_queue(sk->fd, mstate & SNDQ_FIN_ACKED);

	// Send a fin packet to the socket to restore it in a receive queue.
	if (mstate & (RCVQ_FIRST_FIN | RCVQ_SECOND_FIN))
		if (send_fin(sk, data, data_size, TH_ACK | TH_FIN) < 0)
			return -1;

	if (mstate & SNDQ_SECOND_FIN)
		restore_fin_in_snd_queue(sk->fd, mstate & SNDQ_FIN_ACKED);

	if (mstate & RCVQ_FIN_ACKED)
		data->inq_seq++;

	if (mstate & SNDQ_FIN_ACKED) {
		data->outq_seq++;
		if (send_fin(sk, data, data_size, TH_ACK) < 0)
			return -1;
	} */

	return 0;
}
