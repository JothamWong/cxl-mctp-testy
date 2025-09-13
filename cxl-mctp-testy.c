#include <fcntl.h>
#include <linux/limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/cxl_mem.h>
#include <linux/mctp.h>
#include <linux/types.h>

#include "cxl-mctp.h"

/**
    Trivial example program to exercise QEMU FMAPI emulation over MCTP over I2C.

    Exercises creation of LD-FAM.

    Original reference: Jonathan Blow
*/

int sanity_check_rsp(struct cci_msg *req, struct cci_msg *rsp, size_t len,
                     bool fixed_length, size_t min_length) {
  uint32_t pl_length;

  if (len < sizeof(rsp)) {
    printf("Too short to read error code\n");
    return -1;
  }

  if (rsp->category != CXL_MCTP_CATEGORY_RSP) {
    printf("Message not a response\n");
    return -1;
  }
  if (rsp->tag != req->tag) {
    printf("Reply has wrong tag %d %d\n", rsp->tag, req->tag);
    return -1;
  }
  if ((rsp->command != req->command) ||
      (rsp->command_set != req->command_set)) {
    printf("Response to wrong command\n");
    return -1;
  }

  if (rsp->return_code != 0) {
    printf("Error code in response %d\n", rsp->return_code);
    return -1;
  }

  if (fixed_length) {
    if (len != min_length) {
      printf("Not expected fixed length of response. %ld %ld\n", len,
             min_length);
      return -1;
    }
  } else {
    if (len < min_length) {
      printf("Not expected minimum length of response\n");
      return -1;
    }
  }
  pl_length = rsp->pl_length[0] | (rsp->pl_length[1] << 8) |
              ((rsp->pl_length[2] & 0xf) << 16);
  if (len - sizeof(*rsp) != pl_length) {
    printf("Payload length not matching expected part of full message %ld %d\n",
           len - sizeof(*rsp), pl_length);
    return -1;
  }

  return 0;
}

static int parse_identify_rsp(struct cci_infostat_identify_rsp *pl,
                              enum cxl_type *type) {
  enum cxl_type t;

  printf("Infostat Identify Response:\n");
  switch (pl->component_type) {
  case 0x00:
    printf("\tType: Switch\n");
    t = cxl_switch;
    /* PCIe Bridges don't have subsytem IDs, so ignore fields */
    printf("\tVID:%04x DID:%04x\n", pl->vendor_id, pl->device_id);
    break;
  case 0x03:
    printf("\tType: Type3\n");
    t = cxl_type3;
    printf("\tVID:%04x DID:%04x SubsysVID:%04x SubsysID:%04x\n", pl->vendor_id,
           pl->device_id, pl->subsys_vendor_id, pl->subsys_id);
    break;
  default:
    printf("\tType: Unknown\n");
    return -1;
  }
  printf("\tSerial number: 0x%lx\n", *(uint64_t *)pl->serial_num);
  if (type)
    *type = t;

  return 0;
}

static int query_cci_identify(int sd, struct sockaddr_mctp *addr, int *tag,
                              enum cxl_type *type, trans trans_func, int port,
                              int id) {
  int rc;
  struct cci_infostat_identify_rsp *pl;
  struct cci_msg *rsp;
  ssize_t rsp_sz;
  struct cci_msg req = {
      .category = CXL_MCTP_CATEGORY_REQ,
      .tag = *tag++,
      .command = 1,
      .command_set = 0,
      .vendor_ext_status = 0xabcd,
  };

  printf("Information and Status: Identify Request...\n");
  rsp_sz = sizeof(*rsp) + sizeof(*pl);
  rsp = malloc(rsp_sz);
  if (!rsp)
    return -1;

  rc = trans_func(sd, addr, tag, port, id, &req, sizeof(req), rsp, rsp_sz,
                  rsp_sz);
  if (rc) {
    printf("trans fun failed\n");
    goto free_rsp;
  }

  if (rsp->return_code) {
    rc = rsp->return_code;
    goto free_rsp;
  }
  pl = (struct cci_infostat_identify_rsp *)rsp->payload;
  rc = parse_identify_rsp(pl, type);

free_rsp:
  free(rsp);
  return rc;
}

int send_mctp_direct(int sd, struct sockaddr_mctp *addr, int *tag, int port,
                     int ld, struct cci_msg *req_msg, size_t req_msg_sz,
                     struct cci_msg *rsp_msg, size_t rsp_msg_sz,
                     size_t rsp_msg_sz_min) {
  struct sockaddr_mctp addrrx;
  int len;
  socklen_t addrlen;

  len = sendto(sd, req_msg, req_msg_sz, 0, (struct sockaddr *)addr,
               sizeof(*addr));

  len = recvfrom(sd, rsp_msg, rsp_msg_sz, 0, (struct sockaddr *)&addrrx,
                 &addrlen);

  return sanity_check_rsp(req_msg, rsp_msg, len, rsp_msg_sz == rsp_msg_sz_min,
                          rsp_msg_sz_min);
}

int main(int argv, char **argc) {
  if (argv != 2) {
    printf("Usage: ./%s [device]\n", argc[0]);
    return 1;
  }

  int rc, cci_sd;
  int tag = 0;
  int dev_addr;

  trans direct;
  enum cxl_type type;

  struct sockaddr_mctp cci_addr = {.smctp_family = AF_MCTP,
                                   .smctp_network = 11,
                                   .smctp_type = 0x8, /* CXL CCI */
                                   .smctp_tag = MCTP_TAG_OWNER};

  dev_addr = atoi(argc[1]);

  cci_addr.smctp_addr.s_addr = dev_addr;
  cci_sd = socket(AF_MCTP, SOCK_DGRAM, 0);
  rc = bind(cci_sd, (struct sockaddr *)&cci_addr, sizeof(cci_addr));
  if (rc) {
    perror("Bind");
    return -1;
  }
  direct = &send_mctp_direct;
  rc = query_cci_identify(cci_sd, &cci_addr, &tag, &type, direct, 0, 0);
  if (rc)
    goto close_cci_sd;

close_cci_sd:
  close(cci_sd);
  return 0;
}