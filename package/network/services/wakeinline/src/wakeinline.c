/*
ip6tables -A forwarding_wan_rule -p tcp --syn --dport 22 -j NFQUEUE --queue-num 1
*/
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <pwd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/netfilter.h>
#include <netdb.h>
#include <string.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data) {
  struct nfqnl_msg_packet_hdr *ph;
  u_int32_t id;

  ph = nfq_get_msg_packet_hdr(nfa);
  assert (ph);

  id = ntohl(ph->packet_id);

  uint8_t *pkt;
  int len = nfq_get_payload(nfa, &pkt);
  printf("id %d: got %d bytes payload\n", id, len);

  u_int32_t verdict = NF_REPEAT;  /* by default, just mark so we can REJECT */
  if (len >= (signed)sizeof(struct iphdr)) {
    struct iphdr *iph = (struct iphdr *)pkt;
    int af = AF_UNSPEC;
    const void *src;

    if (iph->version == 4) {
      af = AF_INET;
      src = &iph->saddr;
    } else if (iph->version == 6) {
      af = AF_INET6;
      src = &((struct ip6_hdr *)pkt)->ip6_dst;
    } else {
      fprintf(stderr, "weird ip version: %d\n", iph->version);
    }

    if (af != AF_UNSPEC) {
      char dst[47];
      assert(sizeof(dst) >= INET_ADDRSTRLEN &&
             sizeof(dst) >= INET6_ADDRSTRLEN);
      if (inet_ntop(af, src, dst, sizeof(dst))) {
        printf("dst: %s\n", dst);
      }
    }
  }

  int rv;
  rv = nfq_set_verdict2(qh, id, NF_ACCEPT, 1, 0, NULL);
  fprintf(stderr, "set_verdict2: %d\n", rv);
  assert (rv >= 0);

  return 0;
}

static void usage() {
  fprintf(stderr, "Usage: wakeinline [-h dest_hostname ...]\n");
}

int main(int argc, char **argv) {
  struct nfq_handle *h;
  struct nfq_q_handle *qh;
  int fd;
  int rv;
  int opt;
  char buf[4096] __attribute__((aligned));

  h = nfq_open();
  assert (h);

  rv = nfq_unbind_pf(h, AF_INET);
  assert (rv == 0);

  rv = nfq_bind_pf(h, AF_INET);
  assert (rv == 0);

  const u_int16_t kQueueNum = 1;
  void *const kCbData = NULL;
  qh = nfq_create_queue(h, kQueueNum, &cb, kCbData);
  assert (qh);

  const uint32_t kCopyRange = 40;
  assert(kCopyRange >= sizeof(struct iphdr) &&
         kCopyRange >= sizeof(struct ip6_hdr));
  rv = nfq_set_mode(qh, NFQNL_COPY_PACKET, kCopyRange);
  assert (rv == 0);

  fd = nfq_fd(h);
  while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
    nfq_handle_packet(h, buf, rv);
  }

  nfq_destroy_queue(qh);
  nfq_close(h);
  return 0;
}
