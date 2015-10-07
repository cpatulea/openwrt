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
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <strings.h>

#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))

static int my_ether_hostton(const char *hostname, struct ether_addr *e) {
  int rc = -1;

  FILE *fp = fopen("/etc/ethers", "r");
  if (fp == NULL) {
    return rc;
  }

  char line_e[20], line_hostname[50];
  while (!feof(fp) && !ferror(fp)) {
    if (fscanf(fp, "%20s %50s", line_e, line_hostname) == 2) {
      if (!strcasecmp(line_hostname, hostname)) {
        if (!ether_aton_r(line_e, e)) {
          break;
        }

        rc = 0;
        break;
      }
    }
  }

  fclose(fp);
  return rc;
}

static void wake(const char *dst, u_int32_t outdev) {
  int fd;
  struct ifreq ifr;

  // host -> ether
  struct ether_addr ea;
  if (my_ether_hostton(dst, &ea) < 0) {
    perror("ether_hostton");
    return;
  }

  fprintf(stderr, "ea: %s\n", ether_ntoa(&ea));

  // outdev -> broadaddr
  fd = socket(AF_INET, SOCK_DGRAM, 0);
  assert(fd >= 0);

  ifr.ifr_ifindex = outdev;
  if (ioctl(fd, SIOCGIFNAME, &ifr) < 0) {
    perror("ioctl(SIOCGIFNAME)");
    goto out;
  }

  fprintf(stderr, "ifname: %s\n", ifr.ifr_name);

  if (ioctl(fd, SIOCGIFBRDADDR, &ifr) < 0) {
    perror("ioctl(SIOCGIFBRDADDR)");
    goto out;
  }

  if (ifr.ifr_broadaddr.sa_family != AF_INET) {
    fprintf(stderr, "weird broadaddr af: %d\n", ifr.ifr_broadaddr.sa_family);
    goto out;
  }

  struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_broadaddr;
  fprintf(stderr, "brdaddr: %s\n", inet_ntoa(sin->sin_addr));

  // wake
  int one = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one)) < 0) {
    perror("setsockopt(SO_BROADCAST)");
    goto out;
  }

  char magic[6 + 16*6];
  memset(magic, 0xff, 6);
  for (int i = 6; i < sizeof(magic); i += 6) {
    memcpy(&magic[i], &ea.ether_addr_octet, 6);
  }

  sin->sin_port = htons(9);  // discard
  if (sendto(fd, magic, sizeof(magic), 0, (struct sockaddr *)sin,
             sizeof(*sin)) < 0) {
    perror("sendto");
    goto out;
  }

out:
  close(fd);
}

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
        u_int32_t outdev = nfq_get_outdev(nfa);
        fprintf(stderr, "dst: %s outdev: %d\n", dst, outdev);
        wake(dst, outdev);
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
