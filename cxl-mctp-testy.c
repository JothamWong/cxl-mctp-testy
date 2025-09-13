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

/* command effects log uuid */
static const uint8_t cel_uuid[0x10] = {0x0d, 0xa9, 0xc0, 0xb5, 0xbf, 0x41,
                                       0x4b, 0x78, 0x8f, 0x79, 0x96, 0xb1,
                                       0x62, 0x3b, 0x3f, 0x17};

/* vendor debug */
static const uint8_t ven_dbg[0x10] = {0x5e, 0x18, 0x19, 0xd9, 0x11, 0xa9,
                                      0x40, 0x0c, 0x81, 0x1f, 0xd6, 0x07,
                                      0x19, 0x40, 0x3d, 0x86};

/* component state dump */
static const uint8_t c_s_dump[0x10] = {0xb3, 0xfa, 0xb4, 0xcf, 0x01, 0xb6,
                                       0x43, 0x32, 0x94, 0x3e, 0x5e, 0x99,
                                       0x62, 0xf2, 0x35, 0x67};
static const int maxlogs = 10; /* only 3 in CXL r3.0 */

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

static int parse_supported_logs(struct cci_get_supported_logs_rsp *pl,
                                size_t *cel_size) {
  int i, j;

  *cel_size = 0;
  printf("Get Supported Logs Response %d\n",
         min(maxlogs, pl->num_supported_log_entries));

  for (i = 0; i < min(maxlogs, pl->num_supported_log_entries); i++) {
    for (j = 0; j < sizeof(pl->entries[i].uuid); j++) {
      if (pl->entries[i].uuid[j] != cel_uuid[j])
        break;
    }
    if (j == 0x10) {
      *cel_size = pl->entries[i].log_size;
      printf("\tCommand Effects Log available\n");
    }
    for (j = 0; j < sizeof(pl->entries[i].uuid); j++) {
      if (pl->entries[i].uuid[j] != ven_dbg[j])
        break;
    }
    if (j == 0x10)
      printf("\tVendor Debug Log available\n");
    for (j = 0; j < sizeof(pl->entries[i].uuid); j++) {
      if (pl->entries[i].uuid[j] != c_s_dump[j])
        break;
    }
    if (j == 0x10)
      printf("\tComponent State Dump Log available\n");
  }
  if (cel_size == 0) {
    printf("\tNo Command Effects Log - so don't continue\n");
    return -1;
  }
  return 0;
}

static int get_supported_logs(int sd, struct sockaddr_mctp *addr, int *tag,
                              size_t *cel_size, trans trans_func, int port,
                              int id) {
  struct cci_get_supported_logs_rsp *pl;
  struct cci_msg *rsp;
  int rc;
  ssize_t rsp_sz;
  struct cci_msg req = {
      .category = CXL_MCTP_CATEGORY_REQ,
      .tag = *tag++,
      .command = 0,
      .command_set = 4,
      .vendor_ext_status = 0xabcd,
  };

  printf("Supported Logs: Get Request...\n");
  rsp_sz = sizeof(*rsp) + sizeof(*pl) + maxlogs * sizeof(*pl->entries);

  rsp = malloc(rsp_sz);
  if (!rsp)
    return -1;

  rc = trans_func(sd, addr, tag, port, id, &req, sizeof(req), rsp, rsp_sz,
                  sizeof(*rsp) + sizeof(*pl));
  if (rc)
    goto free_rsp;

  pl = (void *)(rsp->payload);
  rc = parse_supported_logs(pl, cel_size);

free_rsp:
  free(rsp);
  return rc;
}

static int get_cel(int sd, struct sockaddr_mctp *addr, int *tag,
                   size_t cel_size, trans trans_func, int port, int id) {
  struct cci_get_log_cel_rsp *pl;
  struct cci_get_log_req *req_pl;
  struct cci_msg *req, *rsp;
  size_t req_sz, rsp_sz;
  int rc = 0;
  int i;

  req_sz = sizeof(*req) + sizeof(*req_pl);
  req = malloc(req_sz);
  if (!req)
    return -1;

  *req = (struct cci_msg){
      .category = CXL_MCTP_CATEGORY_REQ,
      .tag = *tag++,
      .command = 1,
      .command_set = 4,
      .vendor_ext_status = 0xabcd,
      .pl_length =
          {
              [0] = sizeof(*req_pl) & 0xff,
              [1] = (sizeof(*req_pl) >> 8) & 0xff,
              [2] = (sizeof(*req_pl) >> 16) & 0xff,
          },
  };
  req_pl = (struct cci_get_log_req *)req->payload;
  memcpy(req_pl->uuid, cel_uuid, sizeof(req_pl->uuid));
  req_pl->offset = 0;
  req_pl->length = cel_size;

  rsp_sz = sizeof(*rsp) + cel_size;
  rsp = malloc(rsp_sz);
  if (!rsp) {
    rc = -1;
    goto free_req;
  }

  printf("Command Effects Log Requested\n");

  rc = trans_func(sd, addr, tag, port, id, req, req_sz, rsp, rsp_sz, rsp_sz);
  if (rc)
    goto free_rsp;

  pl = (struct cci_get_log_cel_rsp *)rsp->payload;
  printf("Command Effects Log\n");
  for (i = 0; i < cel_size / sizeof(*pl); i++) {
    printf("\t[%04x] %s%s%s%s%s%s%s%s\n", pl[i].opcode,
           pl[i].commandeffect & 0x1 ? "ColdReset " : "",
           pl[i].commandeffect & 0x2 ? "ImConf " : "",
           pl[i].commandeffect & 0x4 ? "ImData " : "",
           pl[i].commandeffect & 0x8 ? "ImPol " : "",
           pl[i].commandeffect & 0x10 ? "ImLog " : "",
           pl[i].commandeffect & 0x20 ? "ImSec" : "",
           pl[i].commandeffect & 0x40 ? "BgOp" : "",
           pl[i].commandeffect & 0x80 ? "SecSup" : "");
  }
free_rsp:
  free(rsp);
free_req:
  free(req);

  return rc;
}

void extract_rsp_msg_from_tunnel(struct cci_msg *tunnel_msg,
                                 struct cci_msg *extracted_msg,
                                 size_t extracted_msg_size) {
  struct cxl_fmapi_tunnel_command_rsp *rsp =
      (struct cxl_fmapi_tunnel_command_rsp *)tunnel_msg->payload;

  memcpy(extracted_msg, &rsp->message, extracted_msg_size);
}

int build_tunnel_req(int *tag, int port_or_ld, struct cci_msg *payload_in,
                     size_t payload_in_sz, struct cci_msg **payload_out,
                     size_t *payload_out_sz) {
  struct cxl_fmapi_tunnel_command_req *t_req;
  struct cci_msg *req;
  size_t t_req_sz = sizeof(*t_req) + payload_in_sz;
  size_t req_sz = sizeof(*req) + t_req_sz;

  req = malloc(req_sz);
  if (!req)
    return -1;

  *req = (struct cci_msg){.category = CXL_MCTP_CATEGORY_REQ,
                          .tag = *tag++,
                          .command = 0,
                          .command_set = 0x53,
                          .vendor_ext_status = 0xabcd,
                          .pl_length = {
                              t_req_sz & 0xff,
                              (t_req_sz >> 8) & 0xff,
                              (t_req_sz >> 16) & 0xff,
                          }};
  t_req = (struct cxl_fmapi_tunnel_command_req *)req->payload;
  *t_req = (struct cxl_fmapi_tunnel_command_req){
      .target_type = TUNNEL_TARGET_TYPE_PORT_OR_LD,
      .id = port_or_ld,
      .command_size = payload_in_sz,
  };
  if (payload_in_sz)
    memcpy(t_req->message, payload_in, payload_in_sz);
  *payload_out = req;
  *payload_out_sz = req_sz;

  return 0;
}

int send_mctp_tunnel1(int sd, struct sockaddr_mctp *addr, int *tag, int port,
                      int ld, struct cci_msg *req_msg, size_t req_msg_sz,
                      struct cci_msg *rsp_msg, size_t rsp_msg_sz,
                      size_t rsp_msg_sz_min) {
  struct cxl_fmapi_tunnel_command_req *t_req;
  struct cxl_fmapi_tunnel_command_rsp *t_rsp;
  struct cci_msg *t_req_msg, *t_rsp_msg;
  struct sockaddr_mctp addrrx;
  size_t t_req_msg_sz, t_rsp_msg_sz, rsp_sz_min, len_max, len_min;
  int len, rc;
  socklen_t addrlen;

  build_tunnel_req(tag, port, req_msg, req_msg_sz, &t_req_msg, &t_req_msg_sz);

  /* Outer CCI message + tunnel header + inner message */
  t_rsp_msg_sz = sizeof(*t_rsp_msg) + sizeof(*t_rsp) + rsp_msg_sz;
  /* These length will be update as tunnel unwound */
  len_min = sizeof(*t_rsp_msg) + sizeof(*t_rsp) + rsp_msg_sz_min;
  len_max = sizeof(*t_rsp_msg) + sizeof(*t_rsp) + rsp_msg_sz;
  t_rsp_msg = malloc(t_rsp_msg_sz);
  if (!t_rsp_msg) {
    rc = -1;
    goto free_req;
  }
  len = sendto(sd, t_req_msg, t_req_msg_sz, 0, (struct sockaddr *)addr,
               sizeof(*addr));
  if (len != t_req_msg_sz) {
    printf("Failed to send whole request\n");
    rc = -1;
    goto free_rsp;
  }

  len = recvfrom(sd, t_rsp_msg, t_rsp_msg_sz, 0, (struct sockaddr *)&addrrx,
                 &addrlen);
  rc = sanity_check_rsp(t_req_msg, t_rsp_msg, len, len_min == len_max, len_min);
  if (rc)
    goto free_rsp;

  /* Update lengths to unwind the outer tunnel */
  len -= sizeof(*t_rsp_msg) + sizeof(*t_rsp);
  len_max -= sizeof(*t_rsp_msg) + sizeof(*t_rsp);
  len_min -= sizeof(*t_rsp_msg) + sizeof(*t_rsp);

  /* Unwind one level of tunnel */
  t_req = (struct cxl_fmapi_tunnel_command_req *)t_req_msg->payload;
  t_rsp = (struct cxl_fmapi_tunnel_command_rsp *)t_rsp_msg->payload;

  if (t_rsp->length != len) {
    printf("Tunnel length is not consistent with received length\n");
    rc = -1;
    goto free_rsp;
  }

  /* Need to exclude the tunneled command header from sizes as used for PL check
   */
  rc = sanity_check_rsp(t_req->message, t_rsp->message, len, len_min == len_max,
                        len_min);
  if (rc)
    goto free_rsp;
  extract_rsp_msg_from_tunnel(t_rsp_msg, rsp_msg, rsp_msg_sz);

free_rsp:
  free(t_rsp_msg);
free_req:
  free(t_req_msg);
  return rc;
}

int send_mctp_tunnel2(int sd, struct sockaddr_mctp *addr, int *tag, int port,
                      int ld, struct cci_msg *req_msg, size_t req_msg_sz,
                      struct cci_msg *rsp_msg, size_t rsp_msg_sz,
                      size_t rsp_msg_sz_min) {
  struct cci_msg *inner_req, *outer_req, *inner_rsp, *outer_rsp;
  size_t inner_req_sz, outer_req_sz, outer_rsp_sz, len_min, len_max;
  struct cxl_fmapi_tunnel_command_req *inner_t_req, *outer_t_req;
  struct cxl_fmapi_tunnel_command_rsp *inner_t_rsp, *outer_t_rsp;
  struct sockaddr_mctp addrrx;
  int len, rc;
  socklen_t addrlen;

  printf("2 Level tunnel of opcode %02x%02x\n", req_msg->command_set,
         req_msg->command);

  rc =
      build_tunnel_req(tag, ld, req_msg, req_msg_sz, &inner_req, &inner_req_sz);
  if (rc)
    return rc;

  rc = build_tunnel_req(tag, port, inner_req, inner_req_sz, &outer_req,
                        &outer_req_sz);

  if (rc)
    goto free_inner_req;

  /*
   * Outer tunnel message + outer tunnel header +
   * inner tunnel message + inner tunnel header +
   * inner message
   */
  outer_rsp_sz = sizeof(*outer_rsp) + sizeof(*outer_t_rsp) +
                 sizeof(*inner_rsp) + sizeof(*inner_t_rsp) + rsp_msg_sz;
  len_min = sizeof(*outer_rsp) + sizeof(*outer_t_rsp) + sizeof(*inner_rsp) +
            sizeof(*inner_t_rsp) + rsp_msg_sz_min;
  len_max = outer_rsp_sz;
  outer_rsp = malloc(outer_rsp_sz);
  if (!outer_rsp) {
    rc = -1;
    goto free_outer_req;
  }

  len = sendto(sd, outer_req, outer_req_sz, 0, (struct sockaddr *)addr,
               sizeof(*addr));
  if (len != outer_req_sz) {
    printf("Failed to send whole request\n");
    rc = -1;
    goto free_outer_rsp;
  }

  len = recvfrom(sd, outer_rsp, outer_rsp_sz, 0, (struct sockaddr *)&addrrx,
                 &addrlen);
  if (len < len_min) {
    printf("Not enough data in reply\n");
    rc = -1;
    goto free_outer_rsp;
  }
  printf("FIrst ooga and len is %d", len);
  rc = sanity_check_rsp(outer_req, outer_rsp, len, len_min == len_max, len_min);
  if (rc)
    goto free_outer_rsp;

  len -= sizeof(*outer_rsp) + sizeof(*outer_t_rsp);
  len_min -= sizeof(*outer_rsp) + sizeof(*outer_t_rsp);
  len_max -= sizeof(*outer_rsp) + sizeof(*outer_t_rsp);

  outer_t_req = (struct cxl_fmapi_tunnel_command_req *)outer_req->payload;
  outer_t_rsp = (struct cxl_fmapi_tunnel_command_rsp *)outer_rsp->payload;

  if (outer_t_rsp->length != len) {
    printf("Tunnel length not consistent with received length\n");
    rc = -1;
    goto free_outer_rsp;
  }

  rc = sanity_check_rsp(outer_t_req->message, outer_t_rsp->message, len,
                        len_min == len_max, len_min);
  if (rc)
    goto free_outer_rsp;

  /*
   * TODO: Consider doing the extra copies so that
   * extract_rsp_msg_from_tunnel() could be used
   */
  inner_rsp = outer_t_rsp->message;
  inner_t_req = (struct cxl_fmapi_tunnel_command_req *)inner_req->payload;
  inner_t_rsp = (struct cxl_fmapi_tunnel_command_rsp *)inner_rsp->payload;

  len -= sizeof(*inner_rsp) + sizeof(*inner_t_rsp);
  len_min -= sizeof(*inner_rsp) + sizeof(*inner_t_rsp);
  len_max -= sizeof(*inner_rsp) + sizeof(*inner_t_rsp);

  if (inner_t_rsp->length != len) {
    printf("Tunnel lenght not consistent with received length\n");
    rc = -1;
    goto free_outer_rsp;
  }
  rc = sanity_check_rsp(inner_t_req->message, inner_t_rsp->message, len,
                        len_min == len_max, len_min);
  if (rc)
    goto free_outer_rsp;

  extract_rsp_msg_from_tunnel(inner_rsp, rsp_msg, rsp_msg_sz);

free_outer_rsp:
  free(outer_rsp);
free_outer_req:
  free(outer_req);
free_inner_req:
  free(inner_req);

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

static int parse_phys_sw_identify_swdev(struct cxl_fmapi_ident_sw_dev_rsp *pl,
                                        int *num_ports) {
  uint8_t *b;

  printf("Physical Switch Identify Switch Device Response:\n");
  printf("\tNum tot vppb %d, Num Bound vPPB %d, Num HDM dec per USP %d\n",
         pl->num_total_vppb, pl->num_active_vppb, pl->num_hdm_decoder_per_usp);
  printf("\tPorts %d\n", pl->num_physical_ports);
  *num_ports = pl->num_physical_ports;
  b = pl->active_port_bitmask;
  printf("\tActivePortMask ");
  for (int i = 0; i < 32; i++)
    printf("%02x", b[i]);
  printf("\n");
  return 0;
}

/* Only directly accessed for now */
int query_physical_switch_info(int sd, struct sockaddr_mctp *addr, int *tag,
                               int *num_ports, trans trans_func, int port,
                               int id) {
  int rc;
  ssize_t rsp_sz;
  struct cci_msg req = {
      .category = CXL_MCTP_CATEGORY_REQ,
      .tag = *tag++,
      .command = CXL_IDENTIFY_SWITCH_DEVICE,
      .command_set = CXL_FM_API_CMD_SET_PHYSICAL_SWITCH,
      .vendor_ext_status = 0xabcd,
  };
  struct cxl_fmapi_ident_sw_dev_rsp *pl;
  struct cci_msg *rsp;

  printf("Physical Switch: Identify Switch Device Request...\n");
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

  pl = (struct cxl_fmapi_ident_sw_dev_rsp *)rsp->payload;
  rc = parse_phys_sw_identify_swdev(pl, num_ports);

free_rsp:
  free(rsp);
  return rc;
}

int parse_phys_port_state_rsp(struct cxl_fmapi_get_phys_port_state_rsp *pl,
                              struct cxl_fmapi_get_phys_port_state_req *reqpl,
                              int *ds_dev_types) {
  printf("Physical Switch Port State Response - num ports %d:\n",
         pl->num_ports);
  for (int i = 0; i < pl->num_ports; i++) {
    struct cxl_fmapi_port_state_info_block *port = &pl->ports[i];
    const char *port_states[] = {[0x0] = "Disabled",
                                 [0x1] = "Bind in progress",
                                 [0x2] = "Unbind in progress",
                                 [0x3] = "DSP",
                                 [0x4] = "USP",
                                 [0x5] = "Reserved",
                                 // other values not present.
                                 [0xf] = "Invalid Port ID"};
    const char *conn_dev_modes[] = {
        [0] = "Not CXL / connected",
        [1] = "CXL 1.1",
        [2] = "CXL 2.0",
    };
    const char *conn_dev_type[] = {
        [0] = "No device detected", [1] = "PCIe device",
        [2] = "CXL type 1 device",  [3] = "CXL type 2 device",
        [4] = "CXL type 3 device",  [5] = "CXL type 3 pooled device",
        [6] = "Reserved",
    };
    const char *ltssm_states[] = {
        [0] = "Detect",    [1] = "Polling",    [2] = "Configuration",
        [3] = "Recovery",  [4] = "L0",         [5] = "L0s",
        [6] = "L1",        [7] = "L2",         [8] = "Disabled",
        [9] = "Loop Back", [10] = "Hot Reset",
    };

    if (port->port_id != reqpl->ports[i]) {
      printf("port id wrong %d %d\n", port->port_id, reqpl->ports[i]);
      return -1;
    }
    printf("Port%02d:\n ", port->port_id);
    printf("\tPort state: ");
    if (port_states[port->config_state & 0xf])
      printf("%s\n", port_states[port->config_state]);
    else
      printf("Unknown state\n");

    /* DSP so device could be there */
    if (port->config_state == 3) {
      printf("\tConnected Device CXL Version: ");
      if (port->conn_dev_cxl_ver > 2)
        printf("Unknown CXL Version\n");
      else
        printf("%s\n", conn_dev_modes[port->conn_dev_cxl_ver]);

      printf("\tConnected Device Type: ");
      ds_dev_types[i] = port->conn_dev_type;
      if (port->conn_dev_type > 7)
        printf("Unknown\n");
      else
        printf("%s\n", conn_dev_type[port->conn_dev_type]);
    }

    printf("\tSupported CXL Modes:");
    if (port->port_cxl_ver_bitmask & 0x1)
      printf(" 1.1");
    if (port->port_cxl_ver_bitmask & 0x2)
      printf(" 2.0");
    printf("\n");

    printf("\tMaximum Link Width: %d Negotiated Width %d\n",
           port->max_link_width, port->negotiated_link_width);
    printf("\tSupported Speeds: ");
    if (port->supported_link_speeds_vector & 0x1)
      printf(" 2.5 GT/s");
    if (port->supported_link_speeds_vector & 0x2)
      printf(" 5.0 GT/s");
    if (port->supported_link_speeds_vector & 0x4)
      printf(" 8.0 GT/s");
    if (port->supported_link_speeds_vector & 0x8)
      printf(" 16.0 GT/s");
    if (port->supported_link_speeds_vector & 0x10)
      printf(" 32.0 GT/s");
    if (port->supported_link_speeds_vector & 0x20)
      printf(" 64.0 GT/s");
    printf("\n");

    printf("\tLTSSM: ");
    if (port->ltssm_state >= sizeof(ltssm_states))
      printf("Unkown\n");
    else
      printf("%s\n", ltssm_states[port->ltssm_state]);
  }
  return 0;
}

/* So far this is only used for direct connected CCIs */
int query_ports(int sd, struct sockaddr_mctp *addr, int *tag, int num_ports,
                int *ds_dev_types, trans trans_func, int port, int id) {
  int rc, i;
  uint8_t *port_list;
  struct cci_msg *req, *rsp;
  struct cxl_fmapi_get_phys_port_state_req *reqpl;
  struct cxl_fmapi_get_phys_port_state_rsp *rsppl;

  size_t req_sz = sizeof(*reqpl) + num_ports + sizeof(*req);
  size_t rsp_sz =
      sizeof(*rsp) + sizeof(*rsppl) + num_ports * sizeof(*rsppl->ports);

  port_list = malloc(sizeof(*port_list) * num_ports);
  if (!port_list)
    return -1;

  for (i = 0; i < num_ports; i++) {
    /* Done like this to allow easy testing of nonsequential lists */
    port_list[i] = i;
  }

  req = malloc(req_sz);
  if (!req) {
    rc = -1;
    goto free_port_list;
  }
  rsp = malloc(rsp_sz);
  if (!rsp) {
    rc = -1;
    goto free_req;
  }

  *req = (struct cci_msg){
      .category = CXL_MCTP_CATEGORY_REQ,
      .tag = *tag++,
      .command = CXL_GET_PHYSICAL_PORT_STATE,
      .command_set = CXL_FM_API_CMD_SET_PHYSICAL_SWITCH,
      .pl_length = {req_sz & 0xff, (req_sz >> 8) & 0xff, (req_sz >> 16) & 0xff},
      .vendor_ext_status = 0x1234,
  };
  reqpl = (void *)req->payload;
  *reqpl = (struct cxl_fmapi_get_phys_port_state_req){
      .num_ports = num_ports,
  };
  for (int j = 0; j < num_ports; j++)
    reqpl->ports[j] = port_list[j];

  printf("Physical Switch Port State Requested\n");
  rc = trans_func(sd, addr, tag, port, id, req, req_sz, rsp, rsp_sz, rsp_sz);
  if (rc)
    goto free_rsp;

  rsppl = (struct cxl_fmapi_get_phys_port_state_rsp *)rsp->payload;

  /* Move to standard check */
  rc = parse_phys_port_state_rsp(rsppl, reqpl, ds_dev_types);
free_port_list:
  free(port_list);
free_rsp:
  free(rsp);
free_req:
  free(req);

  return rc;
}

/* A series of queries that only make sense if first hop hits a switch */
int poke_switch(int dev_addr, bool mctp, int fd, trans direct, trans tunnel1,
                trans tunnel2) {
  struct sockaddr_mctp fmapi_addr = {
      .smctp_family = AF_MCTP,
      .smctp_network = 11,
      .smctp_addr.s_addr = dev_addr,
      .smctp_type = 0x7, /* CXL FMAPI */
      .smctp_tag = MCTP_TAG_OWNER,
  };
  int fmapi_sd, num_ports, i, rc;
  int *ds_dev_types;
  int tag = 42; /* can start anywhere */
  if (mctp) {
    fmapi_sd = socket(AF_MCTP, SOCK_DGRAM, 0);
    rc = bind(fmapi_sd, (struct sockaddr *)&fmapi_addr, sizeof(fmapi_addr));
    if (rc) {
      return -1;
    }
  } else {
    fmapi_sd = fd; /* For Switch CCI no difference */
  }

  rc = query_physical_switch_info(fmapi_sd, &fmapi_addr, &tag, &num_ports,
                                  direct, 0, 0);
  if (rc)
    goto err_close_fd;

  ds_dev_types = malloc(sizeof(*ds_dev_types) * num_ports);
  if (!ds_dev_types) {
    rc = -1;
    goto err_close_fd;
  }

  /* Next query some of the ports */
  rc = query_ports(fmapi_sd, &fmapi_addr, &tag, num_ports, ds_dev_types, direct,
                   0, 0);
  if (rc)
    goto err_free_ds_dev_types;

  for (i = 0; i < num_ports; i++) {
    switch (ds_dev_types[i]) {
    case 5: /* MLD */ {
      size_t cel_size = 0;
      enum cxl_type target_type;
      printf("Query the FM-Owned LD.....\n");
      rc = query_cci_identify(fmapi_sd, &fmapi_addr, &tag, &target_type,
                              tunnel1, i, 0);
      if (rc)
        goto err_free_ds_dev_types;

      rc = get_supported_logs(fmapi_sd, &fmapi_addr, &tag, &cel_size, tunnel1,
                              i, 0);
      if (rc)
        goto err_free_ds_dev_types;

      rc = get_cel(fmapi_sd, &fmapi_addr, &tag, cel_size, tunnel1, i, 0);
      if (rc)
        goto err_free_ds_dev_types;
      printf("Query LD%d.......\n", 0);

      rc = query_cci_identify(fmapi_sd, &fmapi_addr, &tag, &target_type,
                              tunnel2, i, 0);
      if (rc)
        goto err_free_ds_dev_types;
      rc = get_supported_logs(fmapi_sd, &fmapi_addr, &tag, &cel_size, tunnel2,
                              i, 0);
      if (rc)
        goto err_free_ds_dev_types;

      rc = get_cel(fmapi_sd, &fmapi_addr, &tag, cel_size, tunnel2, i, 0);
      if (rc)
        goto err_free_ds_dev_types;

      break;
    }
    default:
      /* Ignoring other types for now */
      break;
    }
  }
err_free_ds_dev_types:
  free(ds_dev_types);
err_close_fd:
  close(fmapi_sd);

  return rc;
}

int main(int argv, char **argc) {
  if (argv != 2) {
    printf("Usage: ./%s [device]\n", argc[0]);
    return 1;
  }

  int rc, cci_sd;
  int tag = 0;
  int dev_addr;

  trans direct;        /* to switch */
  trans tunnel1_level; /* thru switch */
  trans tunnel2_level; /* thru switch */

  enum cxl_type type;
  size_t cel_size;

  struct sockaddr_mctp cci_addr = {.smctp_family = AF_MCTP,
                                   .smctp_network = 11,
                                   .smctp_type = 0x8, /* CXL CCI */
                                   .smctp_tag = MCTP_TAG_OWNER};

  dev_addr = atoi(argc[1]);

  cci_addr.smctp_addr.s_addr = dev_addr;
  cci_sd = socket(AF_MCTP, SOCK_DGRAM, 0);
  if (cci_sd < 0) {
    perror("Socket");
    return -1;
  }
  rc = bind(cci_sd, (struct sockaddr *)&cci_addr, sizeof(cci_addr));
  if (rc) {
    perror("Bind");
    return -1;
  }
  direct = &send_mctp_direct;
  tunnel1_level = &send_mctp_tunnel1;
  tunnel2_level = &send_mctp_tunnel2;

  rc = query_cci_identify(cci_sd, &cci_addr, &tag, &type, direct, 0, 0);
  if (rc)
    goto close_cci_sd;
  rc = get_supported_logs(cci_sd, &cci_addr, &tag, &cel_size, direct, 0, 0);
  if (rc)
    goto close_cci_sd;
  rc = get_cel(cci_sd, &cci_addr, &tag, cel_size, direct, 0, 0);
  if (rc)
    goto close_cci_sd;

  if (type == cxl_switch) {
    rc = poke_switch(dev_addr, true, cci_sd, direct, tunnel1_level,
                     tunnel2_level);
  }

close_cci_sd:
  close(cci_sd);
  return 0;
}