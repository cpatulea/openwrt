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

static const char *dests[5];

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
      struct in_addr daddr = {.s_addr = iph->daddr};
      printf("dest: %s\n", inet_ntoa(daddr));

      for (const char **dest = dests; *dest; ++dest) {
        printf("trying %s\n", *dest);
        struct hostent *he = gethostbyname(*dest);
        if (he) {
          for (char **alp = he->h_addr_list; *alp; ++alp) {
            if (((struct in_addr *)*alp)->s_addr == daddr.s_addr) {
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
  fprintf(stderr, "Usage: namematch [-d dest_hostname ...]\n");
}

int main(int argc, char **argv) {
  struct nfq_handle *h;
  struct nfq_q_handle *qh;
  int fd;
  int rv;
  int opt;
  char buf[4096] __attribute__((aligned));

  size_t dptr = 0;
  while ((opt = getopt(argc, argv, "d:")) != -1) {
    switch (opt) {
    case 'd':
      if (dptr >= ARRAY_SIZE(dests) - 1) {
        fprintf(stderr, "Too many destinations (max %ld).\n",
                ARRAY_SIZE(dests) - 1);
        return 1;
      }
      dests[dptr++] = optarg;
      break;
    default:
      fprintf(stderr, "Unknown option '%c'.\n\n", opt);
      usage();
      return 1;
    }
  }

  if (dptr == 0) {
    fprintf(stderr, "warning: no allowed destinations, dropping all packets\n");
  }
  dests[dptr++] = NULL;

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

  int nobody = getpwnam("nobody")->pw_uid;
  // rv = setresuid(nobody, nobody, nobody);
  assert (rv == 0);

  fd = nfq_fd(h);
  while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
    nfq_handle_packet(h, buf, rv);
  }

  nfq_destroy_queue(qh);
  nfq_close(h);
  return 0;
}
