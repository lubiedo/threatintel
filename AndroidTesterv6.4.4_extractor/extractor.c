// @_lubiedo / @lubiedo
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>

#define FILTER_FMT  "tcp && ((src %s && dst %s) && "\
                    "(src port %d && dst port %d))"
#define MAX_STR_SIZE  PCAP_ERRBUF_SIZE
#define OUTPUT_DIR    "out"

static void process(u_char *user, const struct pcap_pkthdr *h,
  const u_char *data);
static void dump_datastream(void);
static void usage();
static void hexdumb(const char *s, const unsigned int l);
static int  isnum(const char *s);

struct _pkt_data {
  char *buf;
  uint32_t len;
  uint32_t off;
  uint32_t stream_n;
} pkt_data;

static const char *progname;
int vflag = 0, pcap_cnt = 0;
static pcap_t *hpcap;

int
main(int argc, char *argv[])
{
  int   srcport = -1, dstport = -1;
  char  *srchost, *dsthost, *path,
        err[PCAP_ERRBUF_SIZE], filter[PCAP_ERRBUF_SIZE], c;
  struct bpf_program fpcap;

  progname = argv[0];
  while ((c = getopt(argc, argv, "vr:h:p:H:P:")) != -1) {
    switch (c) {
      case 'v':
        vflag = 1;
        break;
      case 'h':
        srchost = optarg;
        break;
      case 'p':
        srcport = atoi(optarg);
        break;
      case 'H':
        dsthost = optarg;
        break;
      case 'P':
        dstport = atoi(optarg);
        break;
      case 'r':
        path = optarg;
        break;
       default:
        usage();
    }
  }
  argc -= optind;
  argv += optind;

  if (
    (!srchost || !dsthost) ||
    (srcport <= 0 || dstport <= 0) || !path)
    usage();
  else
    if (vflag)
      (void)fprintf(stderr, "pcap file: %s\n", path);

  if ((hpcap = pcap_open_offline(path, err)) == NULL) {
    fprintf(stderr, "%s\n", err);
    return 1;
  }

  /* compile filter to be used with the capture */
  (void) snprintf((char *)&filter, PCAP_ERRBUF_SIZE, FILTER_FMT,
    srchost, dsthost, srcport, dstport);
  if (vflag)
    (void)fprintf(stderr, "filter: %s\n", filter);

  if (pcap_compile(hpcap, &fpcap, filter, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
      pcap_setfilter(hpcap, &fpcap)) {
    pcap_perror(hpcap, "filter error");
    return 1;
  }

  /* ok, start processing those */
  if (pcap_loop(hpcap, -1, process, NULL) < 0) {
    pcap_perror(hpcap, "pcap error");
    return 1;
  }
  pcap_close(hpcap);
  return 0;
}

static void
process(u_char *user, const struct pcap_pkthdr *h, const u_char *data)
{
  struct tcphdr thdr;
  int pktoff = 0, data_len;
  char sdata[MAX_STR_SIZE];

  pcap_cnt++;
  /* we want to skip IP header to get to TCP */
  pktoff +=  sizeof(struct ip);
  (void)memcpy(&thdr, (void *)(data + pktoff), sizeof(struct tcphdr));

#ifdef __APPLE__
  if (!htons(thdr.th_ack))
#else
  if (!htons(thdr.ack))
#endif
    return;

  pktoff +=  thdr.th_off * 4;
  data_len = h->len - pktoff;
  if (vflag)
    (void)fprintf(stderr, "packet %02d seq: %u ackseq: %u tcp data len: %u\n",
      pcap_cnt,
#ifdef __APPLE__
        htonl(thdr.th_seq), htonl(thdr.th_ack),
#else
        htonl(thdr.seq), htonl(thdr.ack_seq),
#endif
      data_len);

  /**
  * first check if packet is beginning of data
  * data to be parsed should have the format: {size}\x00[data]
  */
  data += pktoff;
  /* should parse the first number correctly as is an string. */

  (void)sscanf((const char *)data, "%s", (char*)&sdata);
  if (sdata[0] != '\0' && isnum((const char *)sdata)) {
    int data_header_s = strlen(sdata) + 1;

    /* should be the GZIP magic here */
    if (data[data_header_s] == 0x1f && data[data_header_s+1] == 0x8b) {
      data += data_header_s;
      if (vflag)
        (void)fprintf(stderr, "packet %02d type: beginning of data\n",
          pcap_cnt);

      /* packet containing size of data sent */
      pkt_data.stream_n++;
      pkt_data.len = atoi(sdata);
      pkt_data.off = pkt_data.len;

      /* allocate space for buffer */
      pkt_data.buf = (char *)malloc(pkt_data.len);
      (void)memset(pkt_data.buf, 0, pkt_data.len);
      (void)memcpy(pkt_data.buf, data, pkt_data.len);

      /* we already consumed some data */
      pkt_data.off -= data_len - data_header_s;
    }
  } else {
    /* are we done with data */
    if (pkt_data.off > 0) {
      if (vflag)
        (void)fprintf(stderr, "packet %02d type: data stream\n", pcap_cnt);
      (void)memcpy(pkt_data.buf + (pkt_data.len - pkt_data.off), data,
        pkt_data.off);
      pkt_data.off -= data_len;
    }
  }

  if (pkt_data.off <= 0 && pkt_data.stream_n > 0 && data_len > 0) {
    (void)printf("Data stream: %d (size: %d bytes)\n", pkt_data.stream_n,
      pkt_data.len);
    if (vflag)
      hexdumb((const char *)pkt_data.buf, pkt_data.len);
    (void)fflush(stdout);

    dump_datastream();

    if (pkt_data.buf != NULL) {
      (void)free(pkt_data.buf);
      pkt_data.buf = NULL;
    }
  }
}

static void
dump_datastream(void)
{
  char path[MAX_STR_SIZE], *inflated;
  int fd;

  if (vflag && pkt_data.len == 0) {
    (void)fprintf(stderr, "error: cannot write a 0 size buffer");
    return;
  }

  (void)mkdir(OUTPUT_DIR, 0744);
  if (errno > 0 && errno != EEXIST) {
    (void)perror("error");
    return;
  }

  (void)snprintf(&path, MAX_STR_SIZE, "%s/stream_%d.gz", OUTPUT_DIR,
    pkt_data.stream_n);
  if ((fd = open(path, O_WRONLY|O_CREAT, 0644)) == -1) {
    (void)perror("error");
    return;
  }
  (void)write(fd, (void*)pkt_data.buf, pkt_data.len);
  (void)close(fd);
}

static void
usage()
{
  (void)fprintf(stderr, "usage: %s [-v] -r <pcap> -h <src> -p <srcport> -H <dst> -P <dstport>\n", progname);
  exit(1);
}

static void
hexdumb(const char *s, const unsigned int l)
{
  char j = 1;
  for (unsigned int i = 0; i < l; i++) {
    if (s+i == NULL) /* avoid segfaulting */
      break;
    printf("%02x", *(s+i) & 0xff);
    switch (j % 32) {
      case 8:
      case 16:
      case 24:
        printf("    ");
        break;
      case 0:
        putchar('\n');
        break;
      default:
        putchar(' ');
    }

    j = ++j > 32 ? 1 : j;
  }
  putchar('\n');
}

static int
isnum(const char *s)
{
  while (*s != '\0') {
    char c = *(s++);
    if (c > '9' || c < '0')
      return 0;
  }
  return 1;
}
