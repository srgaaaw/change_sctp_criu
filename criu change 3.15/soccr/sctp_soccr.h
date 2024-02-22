#ifndef __LIBSOCCR_SCTP_H__
#define __LIBSOCCR_SCTP_H__
#include <netinet/in.h>		/* sockaddr_in, sockaddr_in6 */
#include <netinet/sctp.h>	/* SCTP_REPAIR_WINDOW, SCTP_TIMESTAMP */
#include <stdint.h>		/* uint32_t */
#include <sys/socket.h>		/* sockaddr */
//#include "soccr.h"

#include "common/config.h"


void libsoccr_sctp_set_log(unsigned int level, void (*fn)(unsigned int level, const char *fmt, ...));

#define SOCCR_SCTP_LOG_ERR	1
#define SOCCR_SCTP_LOG_DBG	2

/*Priya - location is inside /usr/src/linux-headers-4.4.0-174/include/net/sctp/constants.h
Find a way to include it */
/* SCTP state defines for internal state machine */
enum sctp_state {

	SCTP_STATE_CLOSED		= 0,
	SCTP_STATE_COOKIE_WAIT		= 1,
	SCTP_STATE_COOKIE_ECHOED	= 2,
	SCTP_STATE_ESTABLISHED		= 3,
	SCTP_STATE_SHUTDOWN_PENDING	= 4,
	SCTP_STATE_SHUTDOWN_SENT	= 5,
	SCTP_STATE_SHUTDOWN_RECEIVED	= 6,
	SCTP_STATE_SHUTDOWN_ACK_SENT	= 7,

};

union libsoccr_sctp_addr {
	struct sockaddr sa;
	struct sockaddr_in v4;
	struct sockaddr_in6 v6;
};

struct libsoccr_sctp_sk;

struct libsoccr_sctp_sk_data {
	uint8_t		io_event;
	uint8_t		ass_event;
	uint8_t		shut_event;
	uint32_t	num_ostreams;
	uint32_t	max_instreams;
	uint32_t	max_attempts;
	uint32_t	max_init_timeo;
	uint32_t	state;
	uint32_t	inq_len;
	uint32_t	inq_seq;
	uint32_t	outq_len;
	uint32_t	outq_seq;
	uint32_t	unsq_len;
	uint32_t	opt_mask;
	uint32_t	mss_clamp;
	uint32_t	snd_wscale;
	uint32_t	rcv_wscale;
	uint32_t	timestamp;

	uint32_t	flags; /* SOCCR_FLAGS_... below */
	uint32_t	snd_wl1;
	uint32_t	snd_wnd;
	uint32_t	max_window;
	uint32_t	rcv_wnd;
	uint32_t	rcv_wup;
};

struct libsoccr_sctp_sk *libsoccr_sctp_pause(int fd, char repair_check);
int libsoccr_sctp_save(struct libsoccr_sctp_sk *sk, struct libsoccr_sctp_sk_data *data, unsigned data_size);
int libsoccr_sctp_initconfig(struct libsoccr_sctp_sk *sk, struct libsoccr_sctp_sk_data *data, unsigned data_size);
void libsoccr_sctp_release(struct libsoccr_sctp_sk *sk);
void libsoccr_sctp_resume(struct libsoccr_sctp_sk *sk);
int libsoccr_sctp_set_addr(struct libsoccr_sctp_sk *sk, int self, union libsoccr_sctp_addr *addr, unsigned flags);
int libsoccr_set_sctp_initconfig(struct libsoccr_sctp_sk *sk, struct libsoccr_sctp_sk_data *data);
int libsoccr_sctp_restore(struct libsoccr_sctp_sk *sk,
		struct libsoccr_sctp_sk_data *data, unsigned data_size);

#endif
