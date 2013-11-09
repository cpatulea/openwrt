#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <pwd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/netfilter.h>
#include <netdb.h>
#include <string.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))

static const char *hosts[5];

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

  u_int32_t verdict = NF_DROP;
  if (len >= (signed)sizeof(struct iphdr)) {
    struct iphdr *iph = (struct iphdr *)pkt;

    if (iph->version == 4) {
      struct in_addr haddr = {.s_addr = iph->saddr};
      printf("host: %s\n", inet_ntoa(haddr));

      for (const char **host = hosts; *host; ++host) {
        printf("trying %s\n", *host);
        struct hostent *he = gethostbyname(*host);
        if (he) {
          for (char **alp = he->h_addr_list; *alp; ++alp) {
            if (((struct in_addr *)*alp)->s_addr == haddr.s_addr) {
              printf("ok\n");
              verdict = NF_ACCEPT;
              break;
            }
          }
        }

        if (verdict == NF_ACCEPT) break;
      }
    }
  }

  int rv;
  rv = nfq_set_verdict2(qh, id, verdict, 0, 0, NULL);
  fprintf(stderr, "set_verdict2: %d\n", rv);
  assert (rv >= 0);

  return 0;
}

static void usage() {
  fprintf(stderr, "Usage: namematch [-h dest_hostname ...]\n");
}

int main(int argc, char **argv) {
  struct nfq_handle *h;
  struct nfq_q_handle *qh;
  int fd;
  int rv;
  int opt;
  char buf[4096] __attribute__((aligned));

  size_t hptr = 0;
  while ((opt = getopt(argc, argv, "h:")) != -1) {
    switch (opt) {
    case 'h':
      if (hptr >= ARRAY_SIZE(hosts) - 1) {
        fprintf(stderr, "Too many hosts (max %d).\n",
                ARRAY_SIZE(hosts) - 1);
        return 1;
      }
      hosts[hptr++] = optarg;
      break;
    default:
      fprintf(stderr, "Unknown option '%c'.\n\n", opt);
      usage();
      return 1;
    }
  }

  if (hptr == 0) {
    fprintf(stderr, "warning: no allowed destinations, dropping all packets\n");
  }
  hosts[hptr++] = NULL;

  if (optind != argc) {
    fprintf(stderr, "Don't pass any arguments after options.\n\n");
    usage();
    return 1;
  }

  h = nfq_open();
  assert (h);

  rv = nfq_unbind_pf(h, AF_INET);
  assert (rv == 0);

  rv = nfq_bind_pf(h, AF_INET);
  assert (rv == 0);

  const u_int16_t kQueueNum = 0;
  void *const kCbData = NULL;
  qh = nfq_create_queue(h, kQueueNum, &cb, kCbData);
  assert (qh);

  const uint32_t kCopyRange = sizeof(struct iphdr);
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
