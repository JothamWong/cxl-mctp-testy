#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <linux/mctp.h>
#include <linux/types.h>
#include <linux/cxl_mem.h>

#define min(a, b) \
	({ __typeof__ (a) _a = (a); \
	__typeof__ (b) _b = (b); \
	_a < _b ? _a : _b; })

#define CXL_CCI_CMD_SET_INFO 0x0
#define  CXL_IDENTIFY 0x0
#define CXL_FM_API_CMD_SET_PHYSICAL_SWITCH 0x51
#define  CXL_IDENTIFY_SWITCH_DEVICE 0x00
#define  CXL_GET_PHYSICAL_PORT_STATE 0x01


/* Commands in the non device type specific range - use MCTP Type 3 binding */

/* CXL r3.0 Figure 7-19: CCI Message Format */
struct cci_msg {
#define CXL_MCTP_CATEGORY_REQ 0
#define CXL_MCTP_CATEGORY_RSP 1
	uint8_t category;
	uint8_t tag;
	uint8_t rsv1;
	uint8_t command;
	uint8_t command_set;
	uint8_t pl_length[3]; /* 20 bit little endian, BO bit at bit 23 */
	uint16_t return_code;
	uint16_t vendor_ext_status;
	uint8_t payload[];
} __attribute__ ((packed));

/* CXL r3.0 Section 8.2.9.1.1: Identify (Opcode 0001h) */
struct cci_infostat_identify_rsp {
	uint16_t vendor_id;
	uint16_t device_id;
	uint16_t subsys_vendor_id;
	uint16_t subsys_id;
	uint8_t serial_num[8];
	uint8_t max_msg;
	uint8_t component_type;
} __attribute__((packed));

/* CXL r3.0 Section 8.2.9.4.1: Get Timestamp (Opcode 0300h) */
struct cci_get_timestamp_rsp {
	uint64_t timestamp;
} __attribute__((packed));

/* CXL r3.0 Section 8.2.9.5.1: Get Supported Logs (Opcode 0400h) */
struct supported_log_entry {
	uint8_t uuid[0x10];
	uint32_t log_size;
} __attribute__((packed));

struct cci_get_supported_logs_rsp {
	uint16_t num_supported_log_entries;
	uint8_t reserved[6];
	struct supported_log_entry entries[];
} __attribute__((packed));

/*  CXL r3.0 Section 8.2.9.5.2: Get Log (Opcode 0401h) */
struct cci_get_log_req {
	uint8_t uuid[0x10];
	uint32_t offset;
	uint32_t length;
} __attribute__((packed));

struct cci_get_log_cel_rsp {
	uint16_t opcode;
	uint16_t commandeffect;
} __attribute__((packed));

/* Commands using the MCTP FM-API binding */

/* CXL r3.0 Section 7.6.7.1.1: Identify Switch Device (Opcode 5100h) */
struct cxl_fmapi_ident_sw_dev_rsp {
	uint8_t ingres_port_id;
	uint8_t rsv1;
	uint8_t num_physical_ports;
	uint8_t num_vcs;
	uint8_t active_port_bitmask[32];
	uint8_t active_vcs_bitmask[32];
	uint16_t num_total_vppb;
	uint16_t num_active_vppb;
	uint8_t num_hdm_decoder_per_usp;
} __attribute__((packed));

/* CXL r3.0 Section 7.6.7.3.2: Tunnel Management Command (Opcode 5300h) */
struct cxl_fmapi_tunnel_command_req {
	uint8_t id; /* Port or LD ID as appropriate */
	uint8_t target_type;
#define TUNNEL_TARGET_TYPE_PORT_OR_LD  0
#define TUNNEL_TARGET_TYPE_LD_POOL_CCI 1
	uint16_t command_size;
	struct cci_msg message[];
} __attribute__((packed));

struct cxl_fmapi_tunnel_command_rsp {
	uint16_t length;
	uint16_t resv;
	struct cci_msg message[]; /* only one but lets closs over that */
} __attribute__((packed));

/* CXL r3.0 Section 7.6.7.1.2: Get Physical Port State (Opcode 5101h) */
struct cxl_fmapi_get_phys_port_state_req {
	uint8_t num_ports; /* CHECK. may get too large for MCTP message size */
	uint8_t ports[];
} __attribute__((packed));

struct cxl_fmapi_port_state_info_block {
	uint8_t port_id;
	uint8_t config_state;
	uint8_t conn_dev_cxl_ver;
	uint8_t rsv1;
	uint8_t conn_dev_type;
	uint8_t port_cxl_ver_bitmask;
	uint8_t max_link_width;
	uint8_t negotiated_link_width;
	uint8_t supported_link_speeds_vector;
	uint8_t max_link_speed;
	uint8_t current_link_speed;
	uint8_t ltssm_state;
	uint8_t first_lane_num;
	uint16_t link_state;
	uint8_t supported_ld_count;
} __attribute__((packed));

struct cxl_fmapi_get_phys_port_state_rsp {
	uint8_t num_ports;
	uint8_t rsv1[3];
	struct cxl_fmapi_port_state_info_block ports[];
} __attribute__((packed));

enum cxl_type {
    cxl_switch,
    cxl_type3,
};

typedef int (*trans)(int sd, struct sockaddr_mctp *addr, int *tag, int port,
    int ld, struct cci_msg *req_msg, size_t req_msg_sz,
    struct cci_msg *rsp_msg, size_t rsp_msg_sz,
    size_t rsp_msg_min_sze);

int send_mctp_direct(int sd, struct sockaddr_mctp *addr, int *tag, int port,
    int ld, struct cci_msg *req_msg, size_t req_msg_sz,
    struct cci_msg *rsp_msg, size_t rsp_msg_sz,
    size_t rsp_msg_sz_min);