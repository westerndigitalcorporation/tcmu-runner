/*
 * Copyright 2018, Western Digital Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

/*
 * Emulation of a zoned block device supporting Zone Domains and Zone Realms
 * command sets, with a file backstore.
 */

#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <endian.h>
#include <errno.h>
#include <scsi/scsi.h>
#include <linux/types.h>

#include "scsi_defs.h"
#include "libtcmu.h"
#include "tcmu-runner.h"

#define ZBC_HANDLER_SUBTYPE			"dhsmr"

/*
 * SCSI commands.
 */
#define ZBC_OUT					0x94
#define ZBC_IN					0x95
#define ZBC_ZONE_ACTIVATE_32			0x7F /* FIXME value TBD */
#define SANITIZE				0x48
#define RECEIVE_DIAGNOSTIC_RESULTS		0x1C

/*
 * ZBC IN/OUT Service Actions.
 */
#define ZBC_SA_REPORT_ZONES			0x00
#define ZBC_SA_REPORT_REALMS			0x06
#define ZBC_SA_REPORT_ZONE_DOMAINS		0x07
#define ZBC_SA_ZONE_ACTIVATE_16			0x08
#define ZBC_SA_ZONE_QUERY_16			0x09
#define ZBC_SA_REPORT_MUTATIONS			0x05 /* FIXME opcode, SA TBD */

#define ZBC_SA_CLOSE_ZONE			0x01
#define ZBC_SA_FINISH_ZONE			0x02
#define ZBC_SA_OPEN_ZONE			0x03
#define ZBC_SA_RESET_WP				0x04
#define ZBC_SA_SEQUENTIALIZE_ZONE		0x05
#define ZBC_SA_MUTATE				0x06 /* FIXME opcode, SA TBD */

/*
 * ZONE ACTIVATION(32) Service Actions.
 */
#define ZBC_SA_ZONE_ACTIVATE_32			0xF800 /* FIXME value TBD */
#define ZBC_SA_ZONE_QUERY_32			0xF801 /* FIXME value TBD */

/*
 * SCSI additional sense codes.
 */
#define ASC_READ_ERROR				0x1100
#define ASC_WRITE_ERROR				0x0C00
#define ASC_LBA_OUT_OF_RANGE			0x2100
#define ASC_PARAMETER_LIST_LENGTH_ERROR		0x1A00
#define ASC_INVALID_FIELD_IN_CDB		0x2400
#define ASC_INVALID_FIELD_IN_PARAMETER_LIST	0x2600
#define ASC_INTERNAL_TARGET_FAILURE		0x4400

/*
 * ZBC related additional sense codes.
 */
#define ASC_INVALID_COMMAND_OPERATION_CODE	0x2000
#define ASC_UNALIGNED_WRITE_COMMAND		0x2104
#define ASC_WRITE_BOUNDARY_VIOLATION		0x2105
#define ASC_ATTEMPT_TO_READ_INVALID_DATA	0x2106
#define ASC_READ_BOUNDARY_VIOLATION		0x2107
#define ASC_INSUFFICIENT_ZONE_RESOURCES		0x550E
#define ASC_ZONE_IS_OFFLINE			0x2C0E
#define ASC_ZONE_IS_READ_ONLY			0x2708
#define ASC_ZONE_RESET_WP_RECOMMENDED		0x2A16

/*
 * ZBC / Zone Domains additional sense codes.
 */
#define ASC_ZONE_IS_INACTIVE			0x2C12
#define ASC_ATTEMPT_TO_ACCESS_GAP_ZONE		0x2109

/*
 * Maximum supported number zone types (domains) to exist concurrently.
 */
#define ZBC_NR_ZONE_TYPES			4 /* Except GAP zones */

/*
 * REPORT ZONE DOMAINS definitions.
 */
#define ZBC_MAX_DOMAINS				4
#define ZBC_RPT_DOMAINS_HEADER_SIZE		64
#define ZBC_RPT_DOMAINS_RECORD_SIZE		96

#define ZBC_NEW_RPT_REALMS	/* FIXME make unconditional */
/*
 * REPORT REALMS output data definitions.
 */
#define ZBC_RPT_REALMS_HEADER_SIZE		64
#define ZBC_RPT_REALMS_DESC_OFFSET		16
#ifdef ZBC_NEW_RPT_REALMS
 #define ZBC_RR_START_END_DESC_SIZE		32
 #define ZBC_RPT_REALMS_RECORD_SIZE		(ZBC_RPT_REALMS_DESC_OFFSET + \
						 ZBC_RR_START_END_DESC_SIZE * \
						 ZBC_NR_ZONE_TYPES)
#else
 #define ZBC_RPT_REALMS_RECORD_SIZE		128
#endif
#define ZBC_RPT_REALMS_ITEM_SIZE		20

/*
 * REPORT ZONES output data definitions.
 */
#define ZBC_ZONE_DESCRIPTOR_OFFSET		64
#define ZBC_ZONE_DESCRIPTOR_LENGTH		64

/*
 * Activation results header and descriptor sizes.
 */
#define ZBC_ACTV_RES_HEADER_SIZE		64
#define ZBC_ACTV_RES_DESCRIPTOR_SIZE		24

/*
 * Activation status bits to indicate unmet activation prerequisites.
 */
/* Some zones being activated are not inactive */
#define ZBC_ACTV_ERR_NOT_INACTIVE		0x0001

/* Some zones being deactivated are not empty */
#define ZBC_ACTV_ERR_NOT_EMPTY			0x0002

/* Realm alignment violation */
#define ZBC_ACTV_ERR_REALM_ALIGN		0x0004

/* Activation range includes multiple zone types */
#define ZBC_ACTV_ERR_MULTI_TYPES		0x0008

/* Activation of this zone type is unsupported */
#define ZBC_ACTV_ERR_UNSUPP			0x0010

/* Activation range crosses domain boundary */
#define ZBC_ACTV_ERR_MULTI_DOMAINS		0x0020

/*
 * Activation results summary.
 */
#define ZBC_ACTV_STAT_NZP_VALID			0x80 /* NZP value valid */
#define ZBC_ACTV_STAT_ZIWUP_VALID		0x40 /* ZIWUP value valid */
#define ZBC_ACTV_STAT_ACTIVATED			0x01 /* Activated OK */

/*
 * RECEIVE_DIAGNOSTIC_RESULTS definitions.
 */
/* Supported Log Pages Page */
#define ZBC_ZBD_LOG_SUPP_PAGES			0x0

/* Zoned Block Device Stats Page */
#define ZBC_ZBD_LOG_STATS			0x14

/* ZBD Stats log parameter size */
#define ZBC_LOG_PARAM_RECORD_SIZE		12

/* The total number of log parameters in ZBD Stats page */
#define ZBC_NR_STAT_PARAMS			11

/*
 * REPORT MUTATIONS output data definitions.
 * FIXME these values are ad-hoc
 */
#define ZBC_MUTATE_RPT_HEADER_SIZE		32
#define ZBC_MUTATE_RPT_RECORD_SIZE		8
/*
 * SMR device zone model.
 */
enum zbc_smr_dev_model {
	ZBC_HA = 0x00,
	ZBC_HM = 0x14,
};

/*
 * Zone types.
 */
enum zbc_zone_type {
	ZBC_ZONE_TYPE_CONVENTIONAL	= 0x1,
	ZBC_ZONE_TYPE_SEQWRITE_REQ	= 0x2,
	ZBC_ZONE_TYPE_SEQWRITE_PREF	= 0x3,
	ZBC_ZONE_TYPE_SEQ_OR_BEF_REQ	= 0x4,	/* aka SOBR */
	ZBC_ZONE_TYPE_GAP		= 0x5,
};

/*
 * Zone conditions.
 */
enum zbc_zone_cond {
	ZBC_ZONE_COND_NOT_WP	= 0x0,
	ZBC_ZONE_COND_EMPTY	= 0x1,
	ZBC_ZONE_COND_IMP_OPEN	= 0x2,
	ZBC_ZONE_COND_EXP_OPEN	= 0x3,
	ZBC_ZONE_COND_CLOSED	= 0x4,
	ZBC_ZONE_COND_INACTIVE	= 0x5,

	ZBC_ZONE_COND_READONLY	= 0xD,
	ZBC_ZONE_COND_FULL	= 0xE,
	ZBC_ZONE_COND_OFFLINE	= 0xF,
};

/* A special value to indicate that zone write pointer is invalid */
#define ZBC_NO_WP		ULLONG_MAX

/*
 * Metadata zone descriptor.
 */
struct zbc_zone {
	__u64	start;		/* Zone start sector */
	__u64	len;		/* Zone length in number of sectors */
	__u64	wp;		/* Zone write pointer position */
	__u32	next;		/* Next zone in list */
	__u32	prev;		/* Previous zone in list */
	__u8	type;		/* Zone type */
	__u8	cond;		/* Zone condition */
	__u8	non_seq;	/* Non-sequential write resources active */
	__u8	reset;		/* Reset write pointer recommended */
	__u8	reserved[36];
};

/*
 * Test zone (and zone realm) type.
 */
#define zbc_zone_conv(z)	((z)->type == ZBC_ZONE_TYPE_CONVENTIONAL)
#define zbc_zone_seq_req(z)	((z)->type == ZBC_ZONE_TYPE_SEQWRITE_REQ)
#define zbc_zone_seq_pref(z)	((z)->type == ZBC_ZONE_TYPE_SEQWRITE_PREF)
#define zbc_zone_sobr(z)	((z)->type == ZBC_ZONE_TYPE_SEQ_OR_BEF_REQ)
#define zbc_zone_nseq(z)	(zbc_zone_conv(z) || zbc_zone_sobr(z))
#define zbc_zone_seq(z)		(!zbc_zone_nseq(z))
#define zbc_zone_gap(z)		((z)->type == ZBC_ZONE_TYPE_GAP)

/*
 * Test zone conditions.
 */
#define zbc_zone_not_wp(z)	((z)->cond == ZBC_ZONE_COND_NOT_WP)
#define zbc_zone_empty(z)	((z)->cond == ZBC_ZONE_COND_EMPTY)
#define zbc_zone_imp_open(z)	((z)->cond == ZBC_ZONE_COND_IMP_OPEN)
#define zbc_zone_exp_open(z)	((z)->cond == ZBC_ZONE_COND_EXP_OPEN)
#define zbc_zone_is_open(z)	(zbc_zone_imp_open(z) || zbc_zone_exp_open(z))
#define zbc_zone_closed(z)	((z)->cond == ZBC_ZONE_COND_CLOSED)
#define zbc_zone_inactive(z)	((z)->cond == ZBC_ZONE_COND_INACTIVE)
#define zbc_zone_rdonly(z)	((z)->cond == ZBC_ZONE_COND_READONLY)
#define zbc_zone_full(z)	((z)->cond == ZBC_ZONE_COND_FULL)
#define zbc_zone_offline(z)	((z)->cond == ZBC_ZONE_COND_OFFLINE)
#define zbc_zone_rwp(z)		((z)->reset)
#define zbc_zone_non_seq(z)	((z)->non_seq) /* FIXME this one is never set */

/*
 * REPORT ZONES reporting options.
 */
enum zbc_rz_rpt_options {

	/* List all of the zones in the device */
	ZBC_RZ_RO_ALL		= 0x00,

	/* List the zones with a Zone Condition of EMPTY */
	ZBC_RZ_RO_EMPTY		= 0x01,

	/* List the zones with a Zone Condition of IMPLICIT OPEN */
	ZBC_RZ_RO_IMP_OPEN	= 0x02,

	/* List the zones with a Zone Condition of EXPLICIT OPEN */
	ZBC_RZ_RO_EXP_OPEN	= 0x03,

	/* List the zones with a Zone Condition of CLOSED */
	ZBC_RZ_RO_CLOSED	= 0x04,

	/* List the zones with a Zone Condition of FULL */
	ZBC_RZ_RO_FULL		= 0x05,

	/* List the zones with a Zone Condition of READ ONLY */
	ZBC_RZ_RO_READONLY	= 0x06,

	/* List the zones with a Zone Condition of OFFLINE */
	ZBC_RZ_RO_OFFLINE	= 0x07,

	/* List the zones with a Zone Condition of INACTIVE */
	ZBC_RZ_RO_INACTIVE	= 0x08,

	/* 09h to 0Fh Reserved */

	/* List the zones with a zone attribute RESET WP RECOMMENDED set */
	ZBC_RZ_RO_RWP_RECMND	= 0x10,

	/* List the zones with a zone attribute NON_SEQ set */
	ZBC_RZ_RO_NON_SEQ	= 0x11,

	/* 12h to 3dh Reserved */

	/* List of the zones with a Zone Type of GAP */
	ZBC_RZ_RO_GAP		= 0x3e,

	/* List of the zones with a Zone Condition of NOT WP */
	ZBC_RZ_RO_NOT_WP	= 0x3f,

	/* Partial report flag */
	ZBC_RZ_RO_PARTIAL	= 0x80,
};

/*
 * Zone domain flags. These are internal, not a part of the spec.
 */
#define ZBC_DFLG_SMR		0x01	/* Set for SMR domains */

/*
 * Metadata zone domain descriptor.
 */
struct zbc_zone_domain {
	__u64	start_lba;		/* Domain start LBA */
	__u64	end_lba;		/* Domain end LBA */
	__u32	nr_zones;		/* Number of zones in this domain */
	__u8	type;			/* The type of zones in this domain */
	__u8	flags;			/* Zone domain flags */
	__u8	reserved[10];
};

#define zbc_smr_domain(d)	((bool)((d)->flags & ZBC_DFLG_SMR))
#define zbc_cmr_domain(d)	(!zbc_smr_domain(d))

/*
 * REPORT ZONE DOMAINS reporting options.
 */
enum zbc_rzd_rpt_options {

	/* Report all zone domains */
	ZBC_RZD_RO_ALL		= 0x00,

	/* Report all zone domains that for which all zones are active */
	ZBC_RZD_RO_ALL_ACTIVE	= 0x01,

	/* Report all zone domains that have active zones */
	ZBC_RZD_RO_ACTIVE	= 0x02,

	/* Report all zone domains that do not have any active zones */
	ZBC_RZD_RO_INACTIVE	= 0x03,
};

/*
 * Zone realm types.
 */
enum zbc_realm_type {
	ZBC_REALM_TYPE_NOWP	= ZBC_ZONE_TYPE_CONVENTIONAL,
	ZBC_REALM_TYPE_SOBR	= ZBC_ZONE_TYPE_SEQ_OR_BEF_REQ,
	ZBC_REALM_TYPE_SEQ_R	= ZBC_ZONE_TYPE_SEQWRITE_REQ,
	ZBC_REALM_TYPE_SEQ_P	= ZBC_ZONE_TYPE_SEQWRITE_PREF,

	ZBC_REALM_TYPE_MIX	= 0xff, /* Only if no Realms support */
};

#define zbc_realm_nowp(r)	((r)->type == ZBC_REALM_TYPE_NOWP)
#define zbc_realm_sobr(r)	((r)->type == ZBC_REALM_TYPE_SOBR)
#define zbc_realm_conv(r)	(zbc_realm_nowp(r) || zbc_realm_sobr(r))
#define zbc_realm_seq_r(r)	((r)->type == ZBC_REALM_TYPE_SEQ_R)
#define zbc_realm_seq_p(r)	((r)->type == ZBC_REALM_TYPE_SEQ_P)
#define zbc_realm_seq(r)	(zbc_realm_seq_r(r) || zbc_realm_seq_p(r))
#define zbc_realm_mixed(r)	((r)->type == ZBC_REALM_TYPE_MIX)

#define zbc_act_type_nowp(t)	((t) == ZBC_REALM_TYPE_NOWP)
#define zbc_act_type_sobr(t)	((t) == ZBC_REALM_TYPE_SOBR)
#define zbc_act_type_conv(t)	(zbc_act_type_nowp(t) || zbc_act_type_sobr(t))
#define zbc_act_type_seq_r(t)	((t) == ZBC_REALM_TYPE_SEQ_R)
#define zbc_act_type_seq_p(t)	((t) == ZBC_REALM_TYPE_SEQ_P)
#define zbc_act_type_seq(t)	(zbc_act_type_seq_r(t) || zbc_act_type_seq_p(t))

/*
 * Realm flag bits to indicate if a realm
 * can be activated to a particular type.
 */
#define ZBC_ACTV_OF_CONV		(1 << (ZBC_REALM_TYPE_NOWP - 1))
#define ZBC_ACTV_OF_SEQ_REQ		(1 << (ZBC_REALM_TYPE_SEQ_R - 1))
#define ZBC_ACTV_OF_SEQ_PREF		(1 << (ZBC_REALM_TYPE_SEQ_P - 1))
#define ZBC_ACTV_OF_SOBR		(1 << (ZBC_REALM_TYPE_SOBR - 1))

/*
 * Codes for realm restrictions.
 */
#define ZBC_REALM_RESTR_NONE		0x00 /* No restrictions */
#define ZBC_REALM_RESTR_NOACT		0x01 /* No activate/deactivate */
#define ZBC_REALM_RESTR_NOACT_NORWP	0x02 /* Same as NOACT + no WP reset */

/*
 * Metadata for a specific zone type in a realm.
 */
struct zbc_realm_item {
	__u64		start_lba;	/* Realm start LBA */
	__u32		length;		/* Length in zones */
	__u32		start_zone;	/* Index of realm's first zone */
};

/*
 * Metadata zone realm descriptor.
 */
struct zbc_zone_realm {
	__u32		number;		/* Realm number */
	__u8		type;		/* Realm current zone type */
	__u8		flags;		/* Realm activation flags */
	__u8		restr;		/* Realm restrictions */
	__u8		reserved1[1];
	struct zbc_realm_item ri[ZBC_NR_ZONE_TYPES]; /* Indexed by zone type */
};

/*
 * REPORT REALMS reporting options.
 */
enum zbc_rr_rpt_options {

	/* Report all realms */
	ZBC_RR_RO_ALL		= 0x00,

	/* Report all realms that contain active SOBR zones */
	ZBC_RR_RO_SOBR		= 0x01,

	/* Report all realms that contain active SWR zones */
	ZBC_RR_RO_SWR		= 0x02,

	/* Report all realms that contain active SWP zones */
	ZBC_RR_RO_SWP		= 0x03,
};

/*
 * Available mutation device types.
 */
enum zbc_device_type {
	ZBC_MT_UNKNOWN		= 0x00, /* Reserved */
	ZBC_MT_NON_ZONED	= 0x01, /* Non-zoned, PMR device */
	ZBC_MT_HM_ZONED		= 0x02, /* SMR device with HM zone model */
	ZBC_MT_HA_ZONED		= 0x03, /* SMR device with HA zone model */
	ZBC_MT_ZONE_DOM		= 0x04, /* A Zone Domains device */
};

#define zbc_mt_nz(zdev)		((zdev)->dev_type == ZBC_MT_NON_ZONED)
#define zbc_mt_zoned(zdev)	((zdev)->dev_type >= ZBC_MT_HM_ZONED)
#define zbc_mt_hm(zdev)		((zdev)->dev_type == ZBC_MT_HM_ZONED)
#define zbc_mt_ha(zdev)		((zdev)->dev_type == ZBC_MT_HA_ZONED)
#define zbc_mt_zd(zdev)		((zdev)->dev_type == ZBC_MT_ZONE_DOM)

/*
 * FIXME all mutation-related definitions below are ad-hoc,
 * pending a joint proposal at T13/T10 committees.
 */

/*
 * Available options for ZBC_MT_NON_ZONED mutation type.
 */
enum zbc_mutation_opt_nz {
	ZBC_MO_NZ_UNKNOWN	= 0x00, /* Reserved */
	ZBC_MO_NZ_GENERIC	= 0x01, /* Only one configuration for now */
};

/*
 * Available options for ZBC_MT_HM_ZONED and ZBC_MT_HA_ZONED mutation types.
 */
enum zbc_mutation_opt_smr {
	ZBC_MO_SMR_UNKNOWN	= 0x00, /* Reserved */
	ZBC_MO_SMR_NO_CMR	= 0x01, /* SMR with no CMR zones */
	ZBC_MO_SMR_1PCNT_B	= 0x02, /* SMR with 1% of CMR zones at bottom */
	ZBC_MO_SMR_2PCNT_BT	= 0x03, /* SMR with 2% of CMR zones at bottom */
					/* and one CMR zone below high LBA */
	ZBC_MO_SMR_FAULTY	= 0x04, /* SMR with offline and read-only */
					/* zones */
};

/*
 * Available options for ZBC_MT_ZONE_DOM mutation type.
 */
enum zbc_mutation_opt_zd {
	 /* Reserved */
	ZBC_MO_ZD_UNKNOWN	= 0x00,
	/* ZD, SWR, no CMR-only realms */
	ZBC_MO_ZD_NO_CMR	= 0x01,
	/* ZD, one CMR-only realm at bottom */
	ZBC_MO_ZD_1_CMR_BOT	= 0x02,
	/* ZD, one CMR-only realm at bottom and top */
	ZBC_MO_ZD_1_CMR_BOT_TOP = 0x03,
	/* ZD, SOBR initial, no CMR-only realms */
	ZBC_MO_ZD_SOBR_NO_CMR	= 0x04,
	/* ZD, SWR, CMR realms at bottom and top */
	ZBC_MO_ZD_1_CMR_BT_SWR	= 0x05,
	/* ZD, no MODE SELECT control */
	ZBC_MO_ZD_BBONE		= 0x06,
	/* ZD, readonly and offline zones */
	ZBC_MO_ZD_FAULTY	= 0x07,
	/* ZD, like ZBC_MO_ZD_NO_CMR but SWP */
	ZBC_MO_ZD_SWP		= 0x08,
	/* ZD, like ZBC_MO_ZD_SOBR_NO_CMR, but SWP */
	ZBC_MO_ZD_SOBR_SWP	= 0x09,
	/* ZD, like ZBC_MO_ZD_SOBR_NO_CMR, but start EMPTY */
	ZBC_MO_ZD_SOBR_EMPTY	= 0x0a,
	/* ZD, like ZBC_MO_ZD_SOBR_EMPTY, with readonly and offline zones */
	ZBC_MO_ZD_SOBR_FAULTY	= 0x0b,
	/* ZD, like ZBC_MO_ZD_1_CMR_BOT_TOP, but with SOBR */
	ZBC_MO_ZD_1_SOBR_BT_TOP = 0x0c,
};

/*
 * Combined mutation options.
 */
union zbc_mutation_opt {
	enum zbc_mutation_opt_nz nz;
	enum zbc_mutation_opt_smr smr;
	enum zbc_mutation_opt_zd zd;
};

/*
 * Device feature profile. Sets the features that
 * a particular device model has or doesn't have.
 */
struct zbc_dev_features {
	/* The device type that, along with the option, has these features */
	enum zbc_device_type	type;

	/* The mutation option that has this set of features */
	union zbc_mutation_opt	model;

	/* Mutation option name */
	const char		*opt_name;

	/* CMR zone type after format */
	unsigned int		initial_cmr_type;

	/* CMR zone condition after format */
	unsigned int		initial_cmr_cond;

	/* SMR zone type after format */
	unsigned int		initial_smr_type;

	/* SMR zone condition after format */
	unsigned int		initial_smr_cond;

	/* If true, the device should be formatted activated SMR */
	unsigned int		initial_all_smr:1;

	/* If true, the device supports activation of SOBR */
	unsigned int		actv_of_sobr:1;

	/* If true, the device supports activation of Conventional */
	unsigned int		actv_of_conv:1;

	/* If true, device has activation of Sequentional Write Required */
	unsigned int		actv_of_seq_req:1;

	/* If true, device has activation of Sequentional Write Preferred */
	unsigned int		actv_of_seq_pref:1;

	/* If false, setting FSNOZ via MODE SELECT is is supported */
	unsigned int		no_za_control:1;

	/* If true, setting MAXIMUM ACTIVATION value is supported */
	unsigned int		max_act_control:1;

	/* If false, enable/disable URSWRZ is supported */
	unsigned int		no_ur_control:1;

	/* If false, NOZSRC bit in ZONE ACTIVATE/QUERY is supported */
	unsigned int		no_nozsrc:1;

	/* Initial URSWRZ setting. The value is the opposite of URSWRZ */
	unsigned int		initial_wp_check:1;

	/* If true, the device doesn't support REPORT REALMS command */
	unsigned int		no_report_realms:1;

	/* The number of read-only zones */
	size_t			nr_rdonly_zones;

	/*
	 * Offset in domain 0 zone space of the first read-only zone.
	 * Ignored if nr_rdonly_zones == 0.
	 */
	uint64_t		rdonly_zone_offset;

	/* The number of offline zones */
	size_t			nr_offline_zones;

	/*
	 * Offset in domain 0 zone space of the first offline zone.
	 * Ignored if nr_offline_zones == 0.
	 */
	size_t			offline_zone_offset;

	/* Bottom CMR-only zones. Vaiue in % for HM/HA and in realms for ZD */
	unsigned int		nr_bot_cmr;

	/* Top CMR-only zones. Vaiue is in % for HM/HA and in realms for ZD */
	unsigned int		nr_top_cmr;

	/* Initial MAXIMUM ACTIVATION value in zones, 0 = unlimited */
	size_t			max_activate;

	/* Gap between domains in zones, no gap by default */
	unsigned int		domain_gap;
};

/*
 * Metadata magic.
 */
#define META_MAGIC		((__u32)'H' << 24 | \
				 (__u32)'Z' << 16 | \
				 (__u32)'B' << 8 | \
				 (__u32)'C')

#define ZBC_LIST_NIL		UINT_MAX

/*
 * Zones in the same condition can be linked together for more
 * efficient processing. Below is the list head/tail structure definition.
 * If the list is empty, the both "head" and "tail" have the value ZBC_LIST_NIL
 * and the "size" is set to zero.
 */
struct zbc_zone_list {

	/* The index to the zone at the head of the list */
	__u32			head;

	/* The index to the zone at the tail of the list */
	__u32			tail;

	/* The number of zones in the list */
	__u32			size;
	__u32			reserved;
};

/*
 * Disk parameters (metadata).
 */
struct zbc_meta {
	/* Magic */
	__u32			magic;

	/* Version of backing-store format (only change if incompatible) */
	__u32			backstore_version;

	/* Size of this structure in the backing store */
	size_t			sizeof_struct_meta;

	/* Time this structure was (re)initialized from zero */
	time_t			time_create;

	/* Time this structure was last checked by a writer */
	time_t			time_checked;

	/* Backstore file size (B) */
	__u64			bs_size;

	/* Device type - Legacy/Zoned/ZD. Can be changed via mutation */
	__u32			dev_type;

	/* Device model, can be changed via mutation */
	union zbc_mutation_opt	dev_model;

	/* Emulated device maximum physical capacity (LBAs) */
	__u64			phys_capacity;

	/* Zone realm size in (LBAs) */
	__u64			realm_size;

	/* Number of realms */
	__u32			nr_realms;

	/* LBA size (B) */
	__u32			lba_size;

	/* Zone domains. Active domains have non-zero size */
	struct zbc_zone_domain	domains[ZBC_MAX_DOMAINS];

	/* Capacity gain from going from CMR to SMR */
	__u32			smr_gain;

	/* Maximum subsequent number of zones to set via FSNOZ */
	__u32			max_activate;

	/* If == 0, then unrestricted reads are enabled */
	__u32			wp_check;

	/* If == 1, then Realms feature set is enabled */
	__u32			realms_feat_set;

	/* Default number of zones to process by ZONE ACTIVATE */
	__u32			nr_actv_zones;

	/* Zone size in (LBAs) */
	__u32			zone_size;

	/* Number of zones */
	__u32			nr_zones;

	/* Number of conventional zones */
	__u32			nr_conv_zones;

	/* Maximum/optimal number of open zones */
	__u32			nr_open_zones;

	/* List of implicitly open zones */
	struct zbc_zone_list	imp_open_zones;

	/* List of explicitly open zones */
	struct zbc_zone_list	exp_open_zones;

	/* List of closed zones */
	struct zbc_zone_list	closed_zones;

	/* List of Write Pointer zones that are not open or closed */
	struct zbc_zone_list	seq_active_zones;

	/* Compatible extensibility */
	__u64			pad[10];

	/* Cached config string to avoid excessive reformats */
	__u8			cfg_str[PATH_MAX];
};

/*
 * Emulated device configuration.
 * Values come from parsing the configuration string, except for the
 * device size, which is obtained using tcmu_get_device_size().
 */
struct zbc_dev_config {

	/* Backstore file path */
	char			*path;

	/* Device type and model */
	enum zbc_device_type	dev_type;
	union zbc_mutation_opt	dev_model;
	const struct zbc_dev_features *dev_feat;

	/* Desired physical capacity */
	long long		phys_capacity;

	/* Configuration options */
	bool			need_format;
	bool			mutating;
	size_t			lba_size;
	size_t			zone_size;
	unsigned int		conv_num;
	unsigned int		open_num;
	unsigned int		wp_check;

	/* Options for Zone Domains/Realms command sets */
	unsigned long long	realm_size;
	unsigned int		smr_gain;
	unsigned int		max_activate;
	bool			realms_feat_set;

	/* saved copies of dynamically changeable config params */
	unsigned long long	realm_size_cfgstr;
	size_t			zone_size_cfgstr;
	unsigned int		smr_gain_cfgstr;
};

/*
 * Default configuration values.
 */
#define ZBC_CONF_DEFAULT_DEV_TYPE	ZBC_MT_ZONE_DOM
#define ZBC_CONF_DEFAULT_DEV_MODEL	ZBC_MO_ZD_SOBR_NO_CMR
#define ZBC_CONF_DEFAULT_ZSIZE		(256UL * 1024 * 1024)
#define ZBC_CONF_DEFAULT_LBA_SIZE	512
#define ZBC_CONF_DEFAULT_CONV_NUM	(unsigned int)(-1)
#define ZBC_CONF_DEFAULT_OPEN_NUM	128
#define ZBC_CONF_DEFAULT_DOM_SIZE	(ZBC_CONF_DEFAULT_ZSIZE * 10)
#define ZBC_CONF_DEFAULT_DOM_GAIN	125
#define ZBC_CONF_WP_CHECK_NOT_SET	UINT_MAX
#define ZBC_CONF_DEFAULT_WP_CHECK	ZBC_CONF_WP_CHECK_NOT_SET
#define ZBC_CONF_DEFAULT_REALMS_SUPPORT	true
#define ZBC_CONF_DEFAULT_MAX_ACTIVATE	0 /* Unlimited */

#define ZBC_DEFERRED_SENSE_BUF_SIZE	4

/*
 * Mutation options and their features.
 */
static const struct zbc_dev_features zbc_opt_feat[] = {
	{
		.opt_name = "NON_ZONED",
		.type = ZBC_MT_NON_ZONED,
		.model = {ZBC_MO_NZ_GENERIC}
	},
	{
		.opt_name = "HM_ZONED",
		.type = ZBC_MT_HM_ZONED,
		.model = {ZBC_MO_SMR_NO_CMR},
		.initial_cmr_type = ZBC_ZONE_TYPE_CONVENTIONAL,
		.initial_cmr_cond = ZBC_ZONE_COND_NOT_WP,
		.initial_smr_type = ZBC_ZONE_TYPE_SEQWRITE_REQ,
		.initial_smr_cond = ZBC_ZONE_COND_EMPTY,
	},
	{
		.opt_name = "HM_ZONED_1PCNT_B",
		.type = ZBC_MT_HM_ZONED,
		.model = {ZBC_MO_SMR_1PCNT_B},
		.initial_cmr_type = ZBC_ZONE_TYPE_CONVENTIONAL,
		.initial_cmr_cond = ZBC_ZONE_COND_NOT_WP,
		.initial_smr_type = ZBC_ZONE_TYPE_SEQWRITE_REQ,
		.initial_smr_cond = ZBC_ZONE_COND_EMPTY,
		.nr_bot_cmr = 1,
	},
	{
		.opt_name = "HM_ZONED_2PCNT_BT",
		.type = ZBC_MT_HM_ZONED,
		.model = {ZBC_MO_SMR_2PCNT_BT},
		.initial_cmr_type = ZBC_ZONE_TYPE_CONVENTIONAL,
		.initial_cmr_cond = ZBC_ZONE_COND_NOT_WP,
		.initial_smr_type = ZBC_ZONE_TYPE_SEQWRITE_REQ,
		.initial_smr_cond = ZBC_ZONE_COND_EMPTY,
		.nr_bot_cmr = 2,
		.nr_top_cmr = 1,
	},
	{
		.opt_name = "HM_ZONED_FAULTY",
		.type = ZBC_MT_HM_ZONED,
		.model = {ZBC_MO_SMR_FAULTY},
		.initial_cmr_type = ZBC_ZONE_TYPE_CONVENTIONAL,
		.initial_cmr_cond = ZBC_ZONE_COND_NOT_WP,
		.initial_smr_type = ZBC_ZONE_TYPE_SEQWRITE_REQ,
		.initial_smr_cond = ZBC_ZONE_COND_EMPTY,
		.nr_rdonly_zones = 2,
		.rdonly_zone_offset = 7,
		.nr_offline_zones = 2,
		.offline_zone_offset = 11,
	},
	{
		.opt_name = "HA_ZONED",
		.type = ZBC_MT_HA_ZONED,
		.model = {ZBC_MO_SMR_NO_CMR},
		.initial_cmr_type = ZBC_ZONE_TYPE_CONVENTIONAL,
		.initial_cmr_cond = ZBC_ZONE_COND_NOT_WP,
		.initial_smr_type = ZBC_ZONE_TYPE_SEQWRITE_PREF,
		.initial_smr_cond = ZBC_ZONE_COND_EMPTY,
	},
	{
		.opt_name = "HA_ZONED_1PCNT_B",
		.type = ZBC_MT_HA_ZONED,
		.model = {ZBC_MO_SMR_1PCNT_B},
		.initial_cmr_type = ZBC_ZONE_TYPE_CONVENTIONAL,
		.initial_cmr_cond = ZBC_ZONE_COND_NOT_WP,
		.initial_smr_type = ZBC_ZONE_TYPE_SEQWRITE_PREF,
		.initial_smr_cond = ZBC_ZONE_COND_EMPTY,
		.nr_bot_cmr = 1,
	},
	{
		.opt_name = "HA_ZONED_2PCNT_BT",
		.type = ZBC_MT_HA_ZONED,
		.model = {ZBC_MO_SMR_2PCNT_BT},
		.initial_cmr_type = ZBC_ZONE_TYPE_CONVENTIONAL,
		.initial_cmr_cond = ZBC_ZONE_COND_NOT_WP,
		.initial_smr_type = ZBC_ZONE_TYPE_SEQWRITE_PREF,
		.initial_smr_cond = ZBC_ZONE_COND_EMPTY,
		.nr_bot_cmr = 2,
		.nr_top_cmr = 1,
	},
	{
		.opt_name = "ZONE_DOM",
		.type = ZBC_MT_ZONE_DOM,
		.model = {ZBC_MO_ZD_NO_CMR},
		.initial_cmr_type = ZBC_ZONE_TYPE_CONVENTIONAL,
		.initial_cmr_cond = ZBC_ZONE_COND_NOT_WP,
		.initial_smr_type = ZBC_ZONE_TYPE_SEQWRITE_REQ,
		.initial_smr_cond = ZBC_ZONE_COND_EMPTY,
		.actv_of_conv = 1,
		.actv_of_seq_req = 1,
		.max_act_control = 1,
		.max_activate = 64,
		.domain_gap = 3,
	},
	{
		.opt_name = "ZD_1CMR_BOT",
		.type = ZBC_MT_ZONE_DOM,
		.model = {ZBC_MO_ZD_1_CMR_BOT},
		.initial_cmr_type = ZBC_ZONE_TYPE_CONVENTIONAL,
		.initial_cmr_cond = ZBC_ZONE_COND_NOT_WP,
		.initial_smr_type = ZBC_ZONE_TYPE_SEQWRITE_REQ,
		.initial_smr_cond = ZBC_ZONE_COND_EMPTY,
		.actv_of_conv = 1,
		.actv_of_seq_req = 1,
		.actv_of_seq_pref = 1,
		.nr_bot_cmr = 1,
		.max_act_control = 1,
		.max_activate = 64,
	},
	{
		.opt_name = "ZD_1CMR_BOT_SWP",
		.type = ZBC_MT_ZONE_DOM,
		.model = {ZBC_MO_ZD_SWP},
		.initial_cmr_type = ZBC_ZONE_TYPE_CONVENTIONAL,
		.initial_cmr_cond = ZBC_ZONE_COND_NOT_WP,
		.initial_smr_type = ZBC_ZONE_TYPE_SEQWRITE_PREF,
		.initial_smr_cond = ZBC_ZONE_COND_EMPTY,
		.actv_of_conv = 1,
		.actv_of_seq_req = 0,
		.actv_of_seq_pref = 1,
		.nr_bot_cmr = 1,
		.max_act_control = 1,
		.max_activate = 64,
	},
	{
		.opt_name = "ZD_1CMR_BOT_TOP",
		.type = ZBC_MT_ZONE_DOM,
		.model = {ZBC_MO_ZD_1_CMR_BOT_TOP},
		.initial_cmr_type = ZBC_ZONE_TYPE_CONVENTIONAL,
		.initial_cmr_cond = ZBC_ZONE_COND_NOT_WP,
		.initial_smr_type = ZBC_ZONE_TYPE_SEQWRITE_REQ,
		.initial_smr_cond = ZBC_ZONE_COND_EMPTY,
		.actv_of_conv = 1,
		.actv_of_seq_req = 1,
		.actv_of_seq_pref = 1,
		.nr_bot_cmr = 1,
		.nr_top_cmr = 1,
		.max_act_control = 1,
		.max_activate = 64,
	},
	{
		/* Same as ZD_1CMR_BOT_TOP, but initially all SMR */
		.opt_name = "ZD_1CMR_BT_SMR",
		.type = ZBC_MT_ZONE_DOM,
		.model = {ZBC_MO_ZD_1_CMR_BT_SWR},
		.initial_cmr_type = ZBC_ZONE_TYPE_CONVENTIONAL,
		.initial_cmr_cond = ZBC_ZONE_COND_NOT_WP,
		.initial_smr_type = ZBC_ZONE_TYPE_SEQWRITE_REQ,
		.initial_smr_cond = ZBC_ZONE_COND_EMPTY,
		.initial_all_smr = 1,
		.actv_of_conv = 1,
		.actv_of_seq_req = 1,
		.actv_of_seq_pref = 1,
		.nr_bot_cmr = 1,
		.nr_top_cmr = 2,
		.max_act_control = 1,
		.max_activate = 64,
	},
	{
		/* SOBR/SWR ZD device */
		.opt_name = "ZD_SOBR",
		.type = ZBC_MT_ZONE_DOM,
		.model = {ZBC_MO_ZD_SOBR_NO_CMR},
		.initial_cmr_type = ZBC_ZONE_TYPE_SEQ_OR_BEF_REQ,
		.initial_cmr_cond = ZBC_ZONE_COND_FULL,
		.initial_smr_type = ZBC_ZONE_TYPE_SEQWRITE_REQ,
		.initial_smr_cond = ZBC_ZONE_COND_EMPTY,
		.actv_of_sobr = 1,
		.actv_of_seq_req = 1,
		.max_act_control = 1,
		.max_activate = 64,
	},
	{
		/* SOBR/SWP ZD device */
		.opt_name = "ZD_SOBR_SWP",
		.type = ZBC_MT_ZONE_DOM,
		.model = {ZBC_MO_ZD_SOBR_SWP},
		.initial_cmr_type = ZBC_ZONE_TYPE_SEQ_OR_BEF_REQ,
		.initial_cmr_cond = ZBC_ZONE_COND_FULL,
		.initial_smr_type = ZBC_ZONE_TYPE_SEQWRITE_PREF,
		.initial_smr_cond = ZBC_ZONE_COND_EMPTY,
		.actv_of_sobr = 1,
		.actv_of_seq_pref = 1,
		.max_act_control = 1,
		.max_activate = 64,
	},
	{
		/* SOBR/SWR ZD device, SOBR zones start EMPTY */
		.opt_name = "ZD_SOBR_EMPTY",
		.type = ZBC_MT_ZONE_DOM,
		.model = {ZBC_MO_ZD_SOBR_EMPTY},
		.initial_cmr_type = ZBC_ZONE_TYPE_SEQ_OR_BEF_REQ,
		.initial_cmr_cond = ZBC_ZONE_COND_EMPTY,
		.initial_smr_type = ZBC_ZONE_TYPE_SEQWRITE_REQ,
		.initial_smr_cond = ZBC_ZONE_COND_EMPTY,
		.actv_of_sobr = 1,
		.actv_of_seq_req = 1,
		.max_act_control = 1,
		.max_activate = 64
	},
	{
		.opt_name = "ZD_1SOBR_BT_TOP",
		.type = ZBC_MT_ZONE_DOM,
		.model = {ZBC_MO_ZD_1_SOBR_BT_TOP},
		.initial_cmr_type = ZBC_ZONE_TYPE_SEQ_OR_BEF_REQ,
		.initial_cmr_cond = ZBC_ZONE_COND_EMPTY,
		.initial_smr_type = ZBC_ZONE_TYPE_SEQWRITE_REQ,
		.initial_smr_cond = ZBC_ZONE_COND_EMPTY,
		.actv_of_sobr = 1,
		.actv_of_seq_req = 1,
		.actv_of_seq_pref = 1,
		.nr_bot_cmr = 1,
		.nr_top_cmr = 1,
		.max_act_control = 1,
		.max_activate = 64,
	},
	{
		.opt_name = "ZD_BARE_BONE",
		.type = ZBC_MT_ZONE_DOM,
		.model = {ZBC_MO_ZD_BBONE},
		.initial_cmr_type = ZBC_ZONE_TYPE_CONVENTIONAL,
		.initial_cmr_cond = ZBC_ZONE_COND_NOT_WP,
		.initial_smr_type = ZBC_ZONE_TYPE_SEQWRITE_REQ,
		.initial_smr_cond = ZBC_ZONE_COND_EMPTY,
		.actv_of_conv = 1,
		.actv_of_seq_req = 1,
		.no_za_control = 1,
		.no_ur_control = 1,
	},
	{
		.opt_name = "ZD_FAULTY",
		.type = ZBC_MT_ZONE_DOM,
		.model = {ZBC_MO_ZD_FAULTY},
		.initial_cmr_type = ZBC_ZONE_TYPE_CONVENTIONAL,
		.initial_cmr_cond = ZBC_ZONE_COND_NOT_WP,
		.initial_smr_type = ZBC_ZONE_TYPE_SEQWRITE_REQ,
		.initial_smr_cond = ZBC_ZONE_COND_EMPTY,
		.actv_of_conv = 1,
		.actv_of_seq_req = 1,
		.max_act_control = 1,
		.max_activate = 64,
		.nr_rdonly_zones = 2,
		.rdonly_zone_offset = 7,
		.nr_offline_zones = 2,
		.offline_zone_offset = 11,
	},
	{
		/* FAULTY SOBR/SWR ZD device, Fixed zones top and bottom */
		.opt_name = "ZD_SOBR_FAULTY",
		.type = ZBC_MT_ZONE_DOM,
		.model = {ZBC_MO_ZD_SOBR_FAULTY},
		.initial_cmr_type = ZBC_ZONE_TYPE_SEQ_OR_BEF_REQ,
		.initial_cmr_cond = ZBC_ZONE_COND_EMPTY,
		.initial_smr_type = ZBC_ZONE_TYPE_SEQWRITE_REQ,
		.initial_smr_cond = ZBC_ZONE_COND_EMPTY,
		.actv_of_sobr = 1,
		.actv_of_seq_req = 1,
		.max_act_control = 1,
		.nr_bot_cmr = 1,
		.nr_top_cmr = 1,
		.nr_rdonly_zones = 2,
		.rdonly_zone_offset = 7,
		.nr_offline_zones = 2,
		.offline_zone_offset = 11,
	},
};

/*
 * Emulated device descriptor private data.
 */
struct zbc_dev {

	struct tcmu_device	*dev;

	struct zbc_dev_config	cfg;

	int			fd;

	enum zbc_device_type	dev_type;
	union zbc_mutation_opt	dev_model;
	const struct zbc_dev_features *dev_feat;

	unsigned long long	bs_size;
	size_t			meta_size;
	struct zbc_meta		*meta;

	unsigned long long	phys_capacity;
	size_t			lba_size;
	unsigned int		lba_log2;

	size_t			zone_size;
	unsigned int		zone_log2;
	uint32_t		def_sense[ZBC_DEFERRED_SENSE_BUF_SIZE];

	struct zbc_zone		*zones;
	unsigned int		nr_zones;
	unsigned int		nr_conv_zones;
	unsigned int		nr_seq_zones;
	unsigned int		nr_open_zones;
	unsigned int		nr_imp_open;
	unsigned int		nr_exp_open;
	unsigned int		nr_empty_zones;

	struct zbc_zone_domain	*domains;
	unsigned int		nr_domains;
	int			zone_type_to_dom[ZBC_NR_ZONE_TYPES];

	struct zbc_zone_realm	*realms;
	unsigned long long	realm_size;
	unsigned int		nr_realms;
	unsigned int		nr_cmr_realm_zones;
	unsigned int		nr_smr_realm_zones;
	unsigned int		smr_gain;
	unsigned int		max_activate;
	unsigned int		nr_actv_zones;
	bool			wp_check;
	bool			realms_feat_set;
	bool			force_mutate;
	bool			have_gaps;

	unsigned long long	logical_capacity;
	unsigned long long	logical_cmr_capacity;
	unsigned long long	logical_smr_capacity;

	struct zbc_zone_list	*imp_open_zones;
	struct zbc_zone_list	*exp_open_zones;
	struct zbc_zone_list	*closed_zones;
	struct zbc_zone_list	*seq_active_zones;

	/* Number of zones maps, CMR->SMR and SMR->CMR, for a single realm */
	unsigned int		*cmr_nr_zones_to_smr;
	unsigned int		*smr_nr_zones_to_cmr;

	/* Stats */
	unsigned int		max_open_zones;
	unsigned int		max_exp_open_seq_zones;
	unsigned int		max_imp_open_seq_zones;
	unsigned int		max_imp_open_sobr_zones;
	unsigned int		min_empty_zones;
	unsigned int		zones_emptied;
	unsigned int		max_non_seq_zones; /* FIXME not collected */
	unsigned long long	subopt_write_cmds; /* FIXME not collected */
	unsigned long long	cmds_above_opt_lim; /* FIXME not collected */
	unsigned long long	failed_exp_opens;
	unsigned long long	read_rule_fails;
	unsigned long long	write_rule_fails;

	unsigned long long	nr_cdb_cmds;	/* all commands executed */
	unsigned long long	nr_tur_cmds;	/* TEST UNIT READY commands */
	unsigned long long	nr_nh_cmds;	/* commands not handled */
};

static inline int zbc_set_sense(struct tcmulib_cmd *cmd,
				uint8_t sk, uint16_t asc_ascq)
{
	return tcmu_set_sense_data(cmd->sense_buf, sk, asc_ascq);
}

/*
 * Endian conversion helper functions.
 */
static inline void zbc_cpbe16(uint8_t *dest, uint16_t val)
{
	uint16_t tmp = htobe16(val);

	memcpy(dest, &tmp, 2);
}

static inline void zbc_cpbe32(uint8_t *dest, uint32_t val)
{
	uint32_t tmp = htobe32(val);

	memcpy(dest, &tmp, 4);
}

static inline void zbc_cpbe48(uint8_t *dest, uint64_t val)
{
	union {
		uint64_t tmp;
		uint8_t bytes[8];
	} u;

	u.tmp = htobe64(val & 0xffffffffffff);
	memcpy(dest, &u.bytes[2], 6);
}

static inline void zbc_cpbe64(uint8_t *dest, uint64_t val)
{
	uint64_t tmp = htobe64(val);

	memcpy(dest, &tmp, 8);
}

static inline uint16_t zbc_rdbe16(uint8_t *buf)
{
	return be16toh(*(uint16_t *)buf);
}

static inline uint32_t zbc_rdbe32(uint8_t *buf)
{
	return be32toh(*(uint32_t *)buf);
}

static inline uint64_t zbc_rdbe48(uint8_t *buf)
{
	uint8_t tmp[8];

	tmp[0] = '\0';
	tmp[1] = '\0';
	memcpy(&tmp[2], buf, 6);
	return be64toh(*(uint64_t *)tmp) & 0xffffffffffff;
}

static inline uint64_t zbc_rdbe64(uint8_t *buf)
{
	return be64toh(*(uint64_t *)buf);
}

/*
 * Configuration parser functions.
 */
static const char *zbc_parse_dev_type(const char *val,
				      struct zbc_dev_config *cfg,
				      const char **msg)
{
	const struct zbc_dev_features *f = zbc_opt_feat;
	int i, len, nr_opt = ARRAY_SIZE(zbc_opt_feat);

	for (i = 0; i < nr_opt; i++, f++) {
		len = strlen(f->opt_name);
		if (strncmp(val, f->opt_name, len) == 0 &&
				(val[len] == '/' || val[len] == '@')) {
			cfg->dev_type = f->type;
			cfg->dev_model = f->model;
			cfg->dev_feat = f;
			return val + len;
		}
	}

	*msg = "Unsupported device type";
	return NULL;
}

/*
 * This one is kept for compatibility only.
 */
static const char *zbc_parse_model(const char *val, struct zbc_dev_config *cfg,
				   const char **msg)
{

	/* SMR device model */
	if (strncmp(val, "HA", 2) == 0) {
		cfg->dev_type = ZBC_MT_HA_ZONED;
		cfg->dev_model.smr = ZBC_MO_SMR_1PCNT_B;
		return val + 2;
	}

	if (strncmp(val, "HM", 2) == 0) {
		cfg->dev_type = ZBC_MT_HM_ZONED;
		cfg->dev_model.smr = ZBC_MO_SMR_1PCNT_B;
		return val + 2;
	}

	*msg = "Invalid device model";

	return NULL;
}

static const char *zbc_parse_lba(const char *val, struct zbc_dev_config *cfg,
				 const char **msg)
{
	char *end;

	cfg->lba_size = strtoul(val, &end, 10);
	if (cfg->lba_size != 512 && cfg->lba_size != 4096) {
		*msg = "Invalid LBA size";
		return NULL;
	}

	return end;
}

static const char *zbc_parse_zsize(const char *val, struct zbc_dev_config *cfg,
				   const char **msg)
{
	char *end;

	cfg->zone_size = strtoul(val, &end, 10) * 1024;
	if (*end == 'K')
		end++;
	else
		cfg->zone_size *= 1024;
	if (!cfg->zone_size ||
	    (cfg->zone_size & (cfg->zone_size - 1))) {
		*msg = "Invalid zone size";
		return NULL;
	}

	return end;
}

static const char *zbc_parse_conv(const char *val,
				  struct zbc_dev_config *cfg,
				  const char **msg)
{
	char *end;

	cfg->conv_num = strtoul(val, &end, 10);

	return end;
}

static const char *zbc_parse_open(const char *val, struct zbc_dev_config *cfg,
				  const char **msg)
{
	char *end;

	cfg->open_num = strtoul(val, &end, 10);
	if (!cfg->open_num) {
		*msg = "Invalid number of open zones";
		return NULL;
	}

	return end;
}

static const char *zbc_parse_realm_support(const char *val,
					   struct zbc_dev_config *cfg,
					   const char **msg)
{
	if (strncmp(val, "y", 1) == 0) {
		cfg->realms_feat_set = 1;
		return val + 1;
	}
	if (strncmp(val, "n", 1) == 0) {
		cfg->realms_feat_set = 0;
		return val + 1;
	}

	*msg = "Invald Realms support switch, value should be 'y' or 'n'";

	return NULL;
}

static const char *zbc_parse_wp_chk(const char *val,
				    struct zbc_dev_config *cfg,
				    const char **msg)
{
	if (strncmp(val, "y", 1) == 0) {
		cfg->wp_check = 1;
		return val + 1;
	}
	if (strncmp(val, "n", 1) == 0) {
		cfg->wp_check = 0;
		return val + 1;
	}

	*msg = "Invalid WP Check switch, value should be 'y' or 'n'";

	return NULL;
}

static const char *zbc_parse_realm_size(const char *val,
					struct zbc_dev_config *cfg,
					const char **msg)
{
	char *end;

	cfg->realm_size = (unsigned long long)strtoul(val, &end, 10) * 1024;
	if (*end == 'K')
		end++;
	else
		cfg->realm_size *= 1024;
	if (!cfg->realm_size) {
		*msg = "Invalid zone realm size";
		return NULL;
	}

	return end;
}

static const char *zbc_parse_smr_gain(const char *val,
				      struct zbc_dev_config *cfg,
				      const char **msg)
{
	char *end;

	cfg->smr_gain = strtof(val, &end) * 100;
	if (cfg->smr_gain <= 100) {
		*msg = "Invalid zone realm SMR gain";
		return NULL;
	}

	return end;
}

static const char *zbc_parse_max_activate(const char *val,
					  struct zbc_dev_config *cfg,
					  const char **msg)
{
	char *end;

	cfg->max_activate = (unsigned long long)strtoul(val, &end, 10);

	return end;
}

struct zbc_dev_config_param {
	const char	*name;
	const char	*(*parse)(const char *n,
				  struct zbc_dev_config *c, const char **p);
} zbc_params[] = {
	{ "type-",	zbc_parse_dev_type	},	/* Device type */
	{ "model-",	zbc_parse_model		},	/* SMR device model */
	{ "lba-",	zbc_parse_lba		},	/* LBA size */
	{ "zsize-",	zbc_parse_zsize		},	/* Zone size MiB */
	{ "conv-",	zbc_parse_conv		},	/* # of conv zones */
	{ "open-",	zbc_parse_open		},	/* Max exp open zones */
	{ "rsize-",	zbc_parse_realm_size	},	/* Realm size MiB */
	{ "sgain-",	zbc_parse_smr_gain	},	/* SMR/CMR cap gain */
	{ "maxact-",	zbc_parse_max_activate	},	/* Max act. zones */
	{ "wpcheck-",	zbc_parse_wp_chk	},	/* WP check */
	{ "realms-",	zbc_parse_realm_support	},	/* Realms support */
};

/*
 * Get emulated device parameters form the backstore file name
 * in the configuration string.
 */
static bool zbc_parse_config(const char *cfgstring, struct zbc_dev_config *cfg,
			     char **reason)
{
	const char *str, *msg = NULL;
	int i, len = 0;

	/*
	 * Set default configuration values.
	 */
	memset(cfg, 0, sizeof(struct zbc_dev_config));
	cfg->dev_type = ZBC_CONF_DEFAULT_DEV_TYPE;
	cfg->dev_model.smr = ZBC_CONF_DEFAULT_DEV_MODEL;
	cfg->lba_size = ZBC_CONF_DEFAULT_LBA_SIZE;
	cfg->zone_size = ZBC_CONF_DEFAULT_ZSIZE;
	cfg->conv_num = ZBC_CONF_DEFAULT_CONV_NUM;
	cfg->open_num = ZBC_CONF_DEFAULT_OPEN_NUM;
	cfg->realm_size = ZBC_CONF_DEFAULT_DOM_SIZE;
	cfg->smr_gain = ZBC_CONF_DEFAULT_DOM_GAIN;
	cfg->max_activate = ZBC_CONF_DEFAULT_MAX_ACTIVATE;
	cfg->wp_check = ZBC_CONF_DEFAULT_WP_CHECK;
	cfg->realms_feat_set = ZBC_CONF_DEFAULT_REALMS_SUPPORT;

	i = strlen(ZBC_HANDLER_SUBTYPE"/");
	if (strncmp(cfgstring, ZBC_HANDLER_SUBTYPE"/", i) != 0)
		goto err;

	str = (const char *)cfgstring + i;

	if (*str != '/') {

		/* Parse option parameters */
		while (*str && *str != '@') {

			for (i = ARRAY_SIZE(zbc_params) - 1; i >= 0; i--) {
				len = strlen(zbc_params[i].name);
				if (strncmp(str, zbc_params[i].name, len) == 0)
					break;
			}
			if (i < 0) {
				msg = "Invalid option name";
				goto failed;
			}
			str += len;

			str = (zbc_params[i].parse)(str, cfg, &msg);
			if (!str)
				goto failed;

			if (*str != '/')
				break;

			str++;

		}

		if (*str != '@')
			goto err;
		str++;

	}

	cfg->path = strdup(str);
	if (!cfg->path) {
		msg = "Failed to get path";
		goto failed;
	}

	/* Save originals for reversion if dynamic changes cause problems */
	cfg->zone_size_cfgstr = cfg->zone_size;
	cfg->realm_size_cfgstr = cfg->realm_size;
	cfg->smr_gain_cfgstr = cfg->smr_gain;

	return true;

err:
	msg = "Invalid configuration string format";
failed:
	if (!msg || asprintf(reason, "%s", msg) == -1)
		*reason = NULL;
	return false;
}

/*
 * Get device feature profile by its type and model.
 */
static const
struct zbc_dev_features *zbc_get_dev_features(enum zbc_device_type dev_type,
					      union zbc_mutation_opt dev_model)
{
	const struct zbc_dev_features *f = zbc_opt_feat;
	int i, nr_opt = ARRAY_SIZE(zbc_opt_feat);

	for (i = 0; i < nr_opt; i++, f++) {
		if (dev_type == f->type && dev_model.zd == f->model.zd)
			return f;
	}

	return NULL;
}

/*
 * Return metadata size, aligned up on the system page size.
 */
static size_t zbc_meta_size(unsigned int nr_realms, unsigned int nr_zones)
{
	size_t meta_size, pg_size = sysconf(_SC_PAGESIZE) - 1;

	meta_size = sizeof(struct zbc_meta) +
			   nr_realms * sizeof(struct zbc_zone_realm) +
			   nr_zones * sizeof(struct zbc_zone);

	return (meta_size + pg_size - 1) & (~(pg_size - 1));
}

/*
 * Initialize a zone list head.
 */
static inline void zbc_init_zone_list(struct zbc_zone_list *zl)
{
	zl->head = ZBC_LIST_NIL;
	zl->tail = ZBC_LIST_NIL;
	zl->size = 0;
}

/*
 * Check if the zone is not currently included into any zone lisrt.
 */
static inline bool zbc_zone_not_in_list(struct zbc_zone *zone)
{
	return (bool)(zone->prev == 0 && zone->next == 0);
}

/*
 * Get the pointer to the first zone in the specified zone list.
 * Returns NULL if the list is empty.
 */
static inline struct zbc_zone *zbc_first_zone(struct zbc_dev *zdev,
					      struct zbc_zone_list *zl)
{
	if (zl->head == ZBC_LIST_NIL)
		return NULL;
	return &zdev->zones[zl->head];
}

/*
 * Get the pointer to the next zone in the same list.
 * Returns NULL if the zone is the last in this list.
 */
static inline struct zbc_zone *zbc_next_zone(struct zbc_dev *zdev,
					     struct zbc_zone *zone)
{
	if (zone->next == ZBC_LIST_NIL)
		return NULL;
	return &zdev->zones[zone->next];
}

/*
 * Check integrity of the given zone list.
 */
static bool zbc_check_list(struct zbc_dev *zdev,
			   struct zbc_zone_list *zl, unsigned int *failed)
{
	struct zbc_zone *zone, *prev = NULL;
	unsigned int sz = 0, idx;

	if (zl->head != ZBC_LIST_NIL && zl->head >= zdev->nr_zones) {
		*failed = 1;
		return false;
	}
	if (zl->tail != ZBC_LIST_NIL && zl->tail >= zdev->nr_zones) {
		*failed = 2;
		return false;
	}
	for (zone = zbc_first_zone(zdev, zl);
	     zone != NULL;
	     zone = zbc_next_zone(zdev, zone)) {
		if (zbc_zone_not_in_list(zone)) {
			*failed = 3;
			return false;
		}
		if (zone->next != ZBC_LIST_NIL &&
		    zone->next >= zdev->nr_zones) {
			*failed = 4;
			return false;
		}
		if (zone->prev != ZBC_LIST_NIL &&
		    zone->prev >= zdev->nr_zones) {
			*failed = 5;
			return false;
		}
		if (prev != NULL) {
			if (zone->prev == ZBC_LIST_NIL) {
				*failed = 6;
				return false;
			}
			if (&zdev->zones[zone->prev] != prev) {
				*failed = 7;
				return false;
			}
		} else {
			if (zone->prev != ZBC_LIST_NIL) {
				*failed = 8;
				return false;
			}
		}
		prev = zone;
		sz++;
		if (sz > zdev->nr_zones) {
			*failed = 9;
			return false;
		}
	}
	if (prev)
		idx = prev - zdev->zones;

	if (sz != zl->size) {
		*failed = 10;
		return false;
	}
	if (!sz) {
		if (zl->head != ZBC_LIST_NIL) {
			*failed = 11;
			return false;
		}
		if (zl->tail != ZBC_LIST_NIL) {
			*failed = 12;
			return false;
		}
	} else if (sz == 1) {
		if (zl->head != idx) {
			*failed = 13;
			return false;
		}
		if (zl->tail != idx) {
			*failed = 14;
			return false;
		}
	} else {
		if (zl->head == idx) {
			*failed = 15;
			return false;
		}
		if (zl->tail != idx) {
			*failed = 16;
			return false;
		}
		if (zl->head == ZBC_LIST_NIL) {
			*failed = 17;
			return false;
		}
	}

	*failed = 0;
	return true;
}

/*
 * Add a zone at the head of a zone list.
 */
static void zbc_add_zone_head(struct zbc_dev *zdev, struct zbc_zone_list *zl,
			      struct zbc_zone *zone)
{
	unsigned int idx = (unsigned int)(zone - zdev->zones);

	if (!zl->size) {
		zl->head = zl->tail = idx;
		zone->next = zone->prev = ZBC_LIST_NIL;
	} else {
		zdev->zones[zl->head].prev = idx;
		zone->next = zl->head;
		zone->prev = ZBC_LIST_NIL;
		zl->head = idx;
	}

	zl->size++;
}

/*
 * Add a zone at the tail of a zone list.
 */
static void zbc_add_zone_tail(struct zbc_dev *zdev, struct zbc_zone_list *zl,
			      struct zbc_zone *zone)
{
	unsigned int idx = (unsigned int)(zone - zdev->zones);

	if (!zl->size) {
		zl->head = zl->tail = idx;
		zone->next = zone->prev = ZBC_LIST_NIL;
	} else {
		zdev->zones[zl->tail].next = idx;
		zone->prev = zl->tail;
		zone->next = ZBC_LIST_NIL;
		zl->tail = idx;
	}

	zl->size++;
}

/*
 * Remove a zone from a zone list. The zone must be linked in the list.
 */
static void zbc_remove_zone(struct zbc_dev *zdev, struct zbc_zone_list *zl,
			    struct zbc_zone *zone)
{
	unsigned int idx = (unsigned int)(zone - zdev->zones);

	--zl->size;
	if (zl->size == 0) {
		zl->head = ZBC_LIST_NIL;
		zl->tail = ZBC_LIST_NIL;
	} else if (idx == zl->head) {
		zl->head = zone->next;
		zdev->zones[zl->head].prev = ZBC_LIST_NIL;
	} else if (idx == zl->tail) {
		zl->tail = zone->prev;
		zdev->zones[zl->tail].next = ZBC_LIST_NIL;
	} else {
		zdev->zones[zone->next].prev = zone->prev;
		zdev->zones[zone->prev].next = zone->next;
	}

	zone->prev = zone->next = 0;
}

/*
 * Remove a zone from it's list based on it's condition.
 * Noop if the zone is not in a list.
 */
static void zbc_unlink_zone(struct zbc_dev *zdev, struct zbc_zone *zone)
{
	if (zbc_zone_not_in_list(zone))
		return;

	switch (zone->cond) {
	case ZBC_ZONE_COND_IMP_OPEN:
		zbc_remove_zone(zdev, zdev->imp_open_zones, zone);
		break;
	case ZBC_ZONE_COND_EXP_OPEN:
		zbc_remove_zone(zdev, zdev->exp_open_zones, zone);
		break;
	case ZBC_ZONE_COND_CLOSED:
		zbc_remove_zone(zdev, zdev->closed_zones, zone);
		break;
	case ZBC_ZONE_COND_EMPTY:
	case ZBC_ZONE_COND_FULL:
		zbc_remove_zone(zdev, zdev->seq_active_zones, zone);
		break;
	case ZBC_ZONE_COND_NOT_WP:
	case ZBC_ZONE_COND_INACTIVE:
	case ZBC_ZONE_COND_READONLY:
	case ZBC_ZONE_COND_OFFLINE:
	default:
		tcmu_dev_err(zdev->dev,
			     "Zone %llu of wrong condition 0x%x in list\n",
			     zone->start, zone->cond);
	}
}

/*
 * Mmap the metadata portion of the backstore file.
 */
static int zbc_map_meta(struct zbc_dev *zdev, bool ro)
{
	struct zbc_meta *meta;
	struct zbc_zone_domain *d;
	int ret, i, mask = PROT_READ;

	if (!ro)
		mask |= PROT_WRITE;

	/* Mmap metadata */
	meta = mmap(NULL, zdev->meta_size, mask,
			  MAP_SHARED, zdev->fd, 0);
	if (meta == MAP_FAILED) {
		ret = -errno;
		tcmu_dev_err(zdev->dev, "mmap %s failed (%m)\n",
			     zdev->cfg.path);
		return ret;
	}

	if (zbc_mt_zd(zdev)) {
		d = zdev->domains = meta->domains;
		for (i = 0; i < ZBC_MAX_DOMAINS; i++, d++) {
			if (!d->end_lba)
				break;
		}
		zdev->nr_domains = i;

		zdev->realms = (struct zbc_zone_realm *)(meta + 1);
		zdev->zones = (struct zbc_zone *)(zdev->realms +
						  zdev->nr_realms);
	} else {
		zdev->realms = NULL;
		zdev->zones = (struct zbc_zone *)(meta + 1);
	}
	if (!zbc_mt_nz(zdev)) {
		zdev->imp_open_zones = &meta->imp_open_zones;
		zdev->exp_open_zones = &meta->exp_open_zones;
		zdev->closed_zones = &meta->closed_zones;
		zdev->seq_active_zones = &meta->seq_active_zones;
	}

	tcmu_dev_dbg(zdev->dev, "Mapped %zu B of metadata at %p%s\n",
		     zdev->meta_size, meta, ro ? " (readonly)" : "");

	zdev->meta = meta;
	return 0;
}

/*
 * Unmap the metadata portion of the backstore file.
 */
static void zbc_unmap_meta(struct zbc_dev *zdev)
{
	if (zdev->meta) {
		munmap(zdev->meta, zdev->meta_size);
		zdev->meta = NULL;
		zdev->realms = NULL;
		zdev->zones = NULL;
	}
}

/*
 * Flush metadata.
 */
static int zbc_flush_meta(struct zbc_dev *zdev)
{
	int ret;

	ret = msync(zdev->meta, zdev->meta_size, MS_SYNC | MS_INVALIDATE);
	if (ret) {
		ret = -errno;
		tcmu_dev_err(zdev->dev, "msync metadata failed (%m)\n");
		return ret;
	}

	return 0;
}

/*
 * Get realm contents for a particular zone type.
 */
static inline
struct zbc_realm_item *zbc_get_realm_item(struct zbc_zone_realm *r,
					  enum zbc_realm_type rt)
{
	return &r->ri[rt - 1];
}

/*
 * Get start LBA for a particular type in a realm.
 */
static inline uint64_t zbc_realm_start(struct zbc_zone_realm *r,
				       enum zbc_realm_type rt)
{
	return zbc_get_realm_item(r, rt)->start_lba;
}

/*
 * Get length in zones for a particular type in a realm.
 */
static inline uint32_t zbc_realm_length(struct zbc_zone_realm *r,
					enum zbc_realm_type rt)
{
	return zbc_get_realm_item(r, rt)->length;
}

/*
 * Get start zone of a particular type in a realm.
 */
static inline struct zbc_zone *zbc_realm_start_zone(struct zbc_dev *zdev,
						    struct zbc_zone_realm *r,
						    enum zbc_realm_type rt)
{
	return &zdev->zones[zbc_get_realm_item(r, rt)->start_zone];
}

/*
 * Check realm activation flags to see if a particular
 * zone type can be activated in this realm.
 */
static inline bool zbc_can_actv_realm_as(struct zbc_zone_realm *r,
					 enum zbc_realm_type rt)
{
	return r->flags & (1 << (rt - 1));
}

/*
 * Look up a zone realm by input LBA and return it's index.
 */
static int zbc_get_zone_realm(struct zbc_dev *zdev, uint64_t lba,
			      bool lowest, unsigned int *zone_type)
{
	struct zbc_zone_domain *d = zdev->domains;
	struct zbc_zone_realm *realms = zdev->realms;
	uint64_t rlba;
	unsigned int rlen, zt;
	int i, r = 0, l = 0, h = zdev->nr_realms - 1;

	/* Make sure that the LBA lays within a domain */
	for (i = 0; i < zdev->nr_domains; i++, d++) {
		if (lba >= d->start_lba && lba <= d->end_lba)
			break;
	}
	if (i == zdev->nr_domains) {
		tcmu_dev_err(zdev->dev,
			     "Can't find domain for LBA %"PRIu64"\n", lba);
		return -1;
	}
	zt = d->type;

	/* Use binary search to zoom in to the needed realm quicker */
	while (l <= h) {
		r = (l + h) / 2;
		rlba = zbc_realm_start(&realms[r], zt);
		if (rlba == lba)
			break;
		if (rlba < lba)
			l = r + 1;
		else
			h = r - 1;
	}
	if (lba < rlba) {
		if (r == 0) {
			tcmu_dev_err(zdev->dev,
				     "Can't fix up 1st realm, %"PRIu64
				     ", %"PRIu64"\n",
				     lba, rlba);
			return -1;
		}
		r--;
		rlba = zbc_realm_start(&realms[r], zt);
	}
	rlen = zbc_realm_length(&realms[r], zt);

	if (rlen) {
		if (lba < rlba ||
		    lba >= rlba + (rlen << zdev->zone_log2)) {
			tcmu_dev_err(zdev->dev, "LBA not in realm, %"PRIu64
						" vs %"PRIu64"+%u\n",
				     lba, rlba, rlen);
			return -1;
		}
	}

	if (lowest && lba != rlba) {
		tcmu_dev_dbg(zdev->dev,
			"Realm start LBA mismatch, %"PRIu64" vs %"PRIu64"\n",
			lba, rlba);
		return -1;
	}

	if (zone_type)
		*zone_type = zt;

	return r;
}

/*
 * Calculate log2 of a value. Since we only support zone and LBA sizes that
 * equal a power of two, we use this to avoid division by zone_size and
 * lba_size in I/O path.
 */
static inline unsigned int zbc_log2(size_t n)
{
	unsigned int r = 0;

	while (n >>= 1)
		r++;
	return r;
}

/*
 * Get domain ID by zone type.
 */
static inline int zbc_domain_id(struct zbc_dev *zdev, enum zbc_zone_type zt)
{
	return zdev->zone_type_to_dom[zt - 1];
}

/*
 * Get domain ID of a zone.
 */
static inline int zbc_get_zone_domain(struct zbc_dev *zdev,
				      struct zbc_zone *zone)
{
	struct zbc_zone_domain *d = zdev->domains;
	int i;

	if (!zbc_zone_gap(zone)) {
		for (i = 0; i < zdev->nr_domains; i++, d++)
			if (zone->start <= zdev->domains[i].end_lba)
				return i;
	}

	return -1;
}

/*
 * Get a zone descriptor.
 */
static struct zbc_zone *zbc_get_zone(struct zbc_dev *zdev, uint64_t lba,
				     bool lowest)
{
	unsigned int zno;
	struct zbc_zone *zone;

	zno = lba >> zdev->zone_log2;

	if (zno >= zdev->nr_zones) {
		tcmu_dev_warn(zdev->dev, "Zone %i for LBA %"PRIu64
					 " exceeds the highest zone %u\n",
			      zno, lba, zdev->nr_zones - 1);
		return NULL;
	}

	zone = &zdev->zones[zno];
	if (lowest && lba != zone->start) {
		tcmu_dev_warn(zdev->dev, "Zone %i: LBA %"PRIu64
					 " not aligned to start LBA %llu\n",
			      zno, lba, zone->start);
		return NULL;
	}

	return zone;
}

/*
 * Rescale a value in [1:old_max] range to [1:new_max] range.
 */
static int zbc_rescale_in_range(unsigned int val, unsigned int old_max,
				unsigned int new_max)
{
	int res;
	double min = 1.0, v = val;

	res = (int)((new_max - min) * (v - old_max) /
		    (old_max - min) + new_max);
	if (res <= 0)
		res = 1;
	else if (res > new_max)
		res = new_max;

	return res;
}

/*
 * Initialize CMR->SMR and SMR->CMR, mappings of number of zones
 * that will be affected by activations within a realm.
 */
static int zbc_init_nr_zone_maps(struct zbc_dev *zdev)
{
	unsigned int *map;
	int i;

	zdev->cmr_nr_zones_to_smr = calloc(zdev->nr_cmr_realm_zones,
					   sizeof(unsigned int));
	if (!zdev->cmr_nr_zones_to_smr)
		return -ENOMEM;
	zdev->smr_nr_zones_to_cmr = calloc(zdev->nr_smr_realm_zones,
					   sizeof(unsigned int));
	if (!zdev->smr_nr_zones_to_cmr)
		return -ENOMEM;

	map = zdev->cmr_nr_zones_to_smr;
	for (i = 0; i < zdev->nr_cmr_realm_zones; i++, map++) {
		*map = zbc_rescale_in_range(i + 1, zdev->nr_cmr_realm_zones,
					    zdev->nr_smr_realm_zones);
	}

	map = zdev->smr_nr_zones_to_cmr;
	for (i = 0; i < zdev->nr_smr_realm_zones; i++, map++) {
		*map = zbc_rescale_in_range(i + 1, zdev->nr_smr_realm_zones,
					    zdev->nr_cmr_realm_zones);
	}
	return 0;
}

/*
 * Calculate the logical capacity of a Zone Domians device.
 */
static void zbc_calc_total_zd_capacity(struct zbc_dev *zdev)
{
	const struct zbc_dev_features *feat = zdev->dev_feat;
	unsigned long long total_cap = 0LL;
	unsigned int nr_zones = 0, nr_domains = 0, gapz;

	zdev->logical_smr_capacity = zdev->nr_seq_zones << zdev->zone_log2;
	zdev->logical_cmr_capacity = zdev->nr_conv_zones << zdev->zone_log2;

	if (feat->actv_of_conv) {
		total_cap += zdev->logical_cmr_capacity;
		nr_zones += zdev->nr_conv_zones;
		nr_domains++;
	}
	if (feat->actv_of_seq_req) {
		total_cap += zdev->logical_smr_capacity;
		nr_zones += zdev->nr_seq_zones;
		nr_domains++;
	}
	if (feat->actv_of_seq_pref) {
		total_cap += zdev->logical_smr_capacity;
		nr_zones += zdev->nr_seq_zones;
		nr_domains++;
	}
	if (feat->actv_of_sobr) {
		total_cap += zdev->logical_cmr_capacity;
		nr_zones += zdev->nr_conv_zones;
		nr_domains++;
	}

	gapz = (nr_domains - 1) * feat->domain_gap;
	zdev->logical_capacity = total_cap + gapz * zdev->zone_size;
	zdev->nr_zones = nr_zones + gapz;

	zbc_init_nr_zone_maps(zdev);
}

/*
 * Initialize zone type -> domain ID mapping. This mapping
 * is the opposite of the one provided by "domains" array.
 */
static void zbc_init_domain_mapping(struct zbc_dev *zdev)
{
	struct zbc_zone_domain *d;
	int i, j;

	for (i = 0; i < ZBC_NR_ZONE_TYPES; i++) {
		zdev->zone_type_to_dom[i] = -1;
		d = zdev->domains;
		for (j = 0; j < zdev->nr_domains; j++, d++) {
			if (d->type == i + 1) {
				zdev->zone_type_to_dom[i] = j;
				break;
			}
		}
	}

	tcmu_dev_dbg(zdev->dev, "Zone type to domain ID mapping:\n");
	for (i = 0; i < ZBC_NR_ZONE_TYPES; i++) {
		tcmu_dev_dbg(zdev->dev, "%u -> %i\n",
			     i + 1, zdev->zone_type_to_dom[i]);
	}
}

/*
 * Check a zone metadata.
 */
static bool zbc_check_zone(struct zbc_dev *zdev,
			   unsigned int zno, unsigned int *failed)
{
	struct zbc_zone *zone = &zdev->zones[zno];

	switch (zone->type) {
	case ZBC_ZONE_TYPE_CONVENTIONAL:
		break;
	case ZBC_ZONE_TYPE_SEQ_OR_BEF_REQ:
		if (!zbc_mt_zd(zdev)) {
			*failed = 1;
			return false;
		}
		break;
	case ZBC_ZONE_TYPE_SEQWRITE_REQ:
		if (zbc_mt_ha(zdev)) {
			*failed = 2;
			return false;
		}
		break;
	case ZBC_ZONE_TYPE_SEQWRITE_PREF:
		if (zbc_mt_hm(zdev)) {
			*failed = 3;
			return false;
		}
		break;
	case ZBC_ZONE_TYPE_GAP:
		if (!zbc_mt_zd(zdev)) {
			*failed = 4;
			return false;
		}
		break;
	default:
		*failed = 5;
		return false;
	}

	switch (zone->cond) {
	case ZBC_ZONE_COND_NOT_WP:
		if (!zbc_zone_conv(zone) &&
		    !zbc_zone_gap(zone)) {
			*failed = 6;
			return false;
		}
	case ZBC_ZONE_COND_OFFLINE:
	case ZBC_ZONE_COND_READONLY:
		if (zone->wp != ZBC_NO_WP) {
			*failed = 7;
			return false;
		}
		break;
	case ZBC_ZONE_COND_EMPTY:
		if (zbc_zone_conv(zone)) {
			*failed = 8;
			return false;
		}
		if (zone->wp != zone->start) {
			*failed = 9;
			return false;
		}
		break;
	case ZBC_ZONE_COND_EXP_OPEN:
	case ZBC_ZONE_COND_CLOSED:
		if (zbc_zone_nseq(zone)) {
			*failed = 10;
			return false;
		}
		break;
	case ZBC_ZONE_COND_IMP_OPEN:
		if (zbc_zone_conv(zone)) {
			*failed = 11;
			return false;
		}
		if (zone->wp < zone->start ||
		    zone->wp >= zone->start + zone->len) {
			*failed = 12;
			return false;
		}
		break;
	case ZBC_ZONE_COND_FULL:
		if (zbc_zone_conv(zone)) {
			*failed = 13;
			return false;
		}
		if (zbc_zone_sobr(zone)) {
			if (zone->wp != ZBC_NO_WP) {
				*failed = 14;
				return false;
			}
		} else if (zone->wp != zone->start + zone->len) {
			*failed = 15;
			return false;
		}
		break;
	case ZBC_ZONE_COND_INACTIVE:
		if (!zbc_mt_zd(zdev)) {
			*failed = 16;
			return false;
		}
		if (zone->wp != ZBC_NO_WP) {
			*failed = 17;
			return false;
		}
		break;
	default:
		*failed = 18;
		return false;
	}

	if (zno > 0) {
		/* Zone continuity check */
		if ((zone->start - zdev->zones[zno - 1].len) !=
		    zdev->zones[zno - 1].start) {
			*failed = 19;
			return false;
		}
	}
	if (zone->start % zdev->zone_size || zone->len > zdev->zone_size) {
		*failed = 20;
		return false;
	}

	*failed = 0;
	return true;
}

/*
 * Check zone domain metadata.
 */
static bool zbc_check_zone_domains(struct zbc_dev *zdev,
				   unsigned int *failed)
{
	struct zbc_zone_domain *d = zdev->domains;
	const struct zbc_dev_features *feat = zdev->dev_feat;
	int i;
	bool have_type;

	if (!zdev->nr_domains) {
		*failed = 1;
		return false;
	}

	if (d->start_lba != 0LL) {
		*failed = 2;
		return false;
	}

	for (i = 0; i < zdev->nr_domains; i++, d++) {
		if (d->end_lba == 0LL) {
			*failed = 3;
			break;
		}
		if (d->start_lba % zdev->zone_size) {
			*failed = 4;
			break;
		}
		if ((d->end_lba + 1) % zdev->zone_size) {
			*failed = 5;
			break;
		}
		if (d->end_lba - d->start_lba > zdev->phys_capacity) {
			*failed = 6;
			return false;
		}
		if (i > 0) {
			if (d->start_lba <= (d - 1)->start_lba) {
				*failed = 7;
				return false;
			}
			if (d->start_lba <= (d - 1)->end_lba) {
				*failed = 8;
				return false;
			}
		}
		if (d->nr_zones !=
		    (d->end_lba - d->start_lba + 1) / zdev->zone_size) {
			*failed = 9;
			return false;
		}

		switch (d->type) {
		case ZBC_ZONE_TYPE_CONVENTIONAL:
			if (!feat->actv_of_conv) {
				*failed = 10;
				return false;
			}
			break;
		case ZBC_ZONE_TYPE_SEQWRITE_REQ:
			if (!feat->actv_of_seq_req) {
				*failed = 11;
				return false;
			}
			break;
		case ZBC_ZONE_TYPE_SEQWRITE_PREF:
			if (!feat->actv_of_seq_pref) {
				*failed = 12;
				return false;
			}
			break;
		case ZBC_ZONE_TYPE_SEQ_OR_BEF_REQ:
			if (!feat->actv_of_sobr) {
				*failed = 13;
				return false;
			}
			break;
		default:
			*failed = 14;
			return false;
		}
	}

	if (feat->actv_of_conv) {
		have_type = false;
		d = zdev->domains;
		for (i = 0; i < zdev->nr_domains; i++, d++) {
			if (d->type == ZBC_ZONE_TYPE_CONVENTIONAL) {
				if (have_type) {
					*failed = 15;
					return false;
				}
				have_type = true;
				if (zbc_smr_domain(d)) {
					*failed = 16;
					return false;
				}
			}
		}
		if (!have_type) {
			*failed = 17;
			return false;
		}
	}
	if (feat->actv_of_seq_req) {
		have_type = false;
		d = zdev->domains;
		for (i = 0; i < zdev->nr_domains; i++, d++) {
			if (d->type == ZBC_ZONE_TYPE_SEQWRITE_REQ) {
				if (have_type) {
					*failed = 18;
					return false;
				}
				have_type = true;
				if (zbc_cmr_domain(d)) {
					*failed = 19;
					return false;
				}
			}
		}
		if (!have_type) {
			*failed = 20;
			return false;
		}
	}
	if (feat->actv_of_seq_pref) {
		have_type = false;
		d = zdev->domains;
		for (i = 0; i < zdev->nr_domains; i++, d++) {
			if (d->type == ZBC_ZONE_TYPE_SEQWRITE_PREF) {
				if (have_type) {
					*failed = 21;
					return false;
				}
				have_type = true;
				if (zbc_cmr_domain(d)) {
					*failed = 22;
					return false;
				}
			}
		}
		if (!have_type) {
			*failed = 23;
			return false;
		}
	}
	if (feat->actv_of_sobr) {
		have_type = false;
		d = zdev->domains;
		for (i = 0; i < zdev->nr_domains; i++, d++) {
			if (d->type == ZBC_ZONE_TYPE_SEQ_OR_BEF_REQ) {
				if (have_type) {
					*failed = 24;
					return false;
				}
				have_type = true;
				if (zbc_smr_domain(d)) {
					*failed = 25;
					return false;
				}
			}
		}
		if (!have_type) {
			*failed = 26;
			return false;
		}
	}

	*failed = 0;
	return true;
}

/*
 * Check that all zone lists are self-consistent.
 */
static bool zbc_check_zone_lists(struct zbc_dev *zdev, unsigned int *failed)
{
	struct zbc_zone_list *zl;
	struct zbc_zone *zone;
	unsigned int i, cnt, lst_failed;

	/* Check the implicitly open zone list */
	zl = zdev->imp_open_zones;
	if (!zbc_check_list(zdev, zl, &lst_failed)) {
		tcmu_dev_err(zdev->dev,
			     "Implicit open zone list check #%u failed\n",
			     lst_failed);
		*failed = 1;
		return false;
	}
	for (zone = zbc_first_zone(zdev, zl);
	     zone != NULL;
	     zone = zbc_next_zone(zdev, zone)) {

		if (zbc_zone_conv(zone)) {
			*failed = 2;
			return false;
		}
		if (!zbc_zone_imp_open(zone)) {
			*failed = 3;
			return false;
		}
	}
	cnt  = 0;
	for (i = 0, zone = zdev->zones; i < zdev->nr_zones; i++, zone++)
		if (zbc_zone_imp_open(zone))
			cnt++;
	if (cnt != zl->size) {
		*failed = 4;
		return false;
	}

	/* Check the explicitly open zone list */
	zl = zdev->exp_open_zones;
	if (!zbc_check_list(zdev, zl, &lst_failed)) {
		tcmu_dev_err(zdev->dev,
			     "Explicit open zone list check #%u failed\n",
			     lst_failed);
		*failed = 5;
		return false;
	}
	for (zone = zbc_first_zone(zdev, zl);
	     zone != NULL;
	     zone = zbc_next_zone(zdev, zone)) {

		if (zbc_zone_conv(zone)) {
			*failed = 6;
			return false;
		}
		if (!zbc_zone_exp_open(zone)) {
			*failed = 7;
			return false;
		}
	}
	cnt  = 0;
	for (i = 0, zone = zdev->zones; i < zdev->nr_zones; i++, zone++)
		if (zbc_zone_exp_open(zone))
			cnt++;
	if (cnt != zl->size) {
		*failed = 8;
		return false;
	}

	/* Check the closed zone list */
	zl = zdev->closed_zones;
	if (!zbc_check_list(zdev, zl, &lst_failed)) {
		tcmu_dev_err(zdev->dev,
			     "Closed open zone list check #%u failed\n",
			     lst_failed);
		*failed = 9;
		return false;
	}
	for (zone = zbc_first_zone(zdev, zl);
	     zone != NULL;
	     zone = zbc_next_zone(zdev, zone)) {

		if (zbc_zone_conv(zone)) {
			*failed = 10;
			return false;
		}
		if (!zbc_zone_closed(zone)) {
			*failed = 11;
			return false;
		}
	}
	cnt = 0;
	for (i = 0, zone = zdev->zones; i < zdev->nr_zones; i++, zone++)
		if (zbc_zone_closed(zone))
			cnt++;
	if (cnt != zl->size) {
		*failed = 12;
		return false;
	}

	/* Check the sequential active zone list */
	zl = zdev->seq_active_zones;
	if (!zbc_check_list(zdev, zl, &lst_failed)) {
		tcmu_dev_err(zdev->dev,
			     "Sequential active zone list check #%u failed\n",
			     lst_failed);
		*failed = 13;
		return false;
	}
	for (zone = zbc_first_zone(zdev, zl);
	     zone != NULL;
	     zone = zbc_next_zone(zdev, zone)) {

		if (zbc_zone_conv(zone)) {
			*failed = 14;
			return false;
		}
		if (zbc_zone_closed(zone)) {
			*failed = 15;
			return false;
		}
		if (zbc_zone_imp_open(zone)) {
			*failed = 16;
			return false;
		}
		if (zbc_zone_inactive(zone)) {
			*failed = 17;
			return false;
		}
		if (zbc_zone_offline(zone)) {
			*failed = 18;
			return false;
		}
		if (zbc_zone_rdonly(zone)) {
			*failed = 19;
			return false;
		}
	}
	cnt = 0;
	for (i = 0, zone = zdev->zones; i < zdev->nr_zones; i++, zone++) {
		if ((zbc_zone_seq(zone) || zbc_zone_sobr(zone)) &&
		    (zbc_zone_empty(zone) || zbc_zone_full(zone)))
			cnt++;
	}
	if (cnt != zl->size) {
		*failed = 20;
		return false;
	}

	*failed = 0;
	return true;
}

/*
 * Validate metadata entry of a zone realm.
 */
static bool zbc_check_zone_realm(struct zbc_dev *zdev,
				 unsigned int rno, unsigned int *failed)
{
	struct zbc_zone_realm *r = &zdev->realms[rno];
	struct zbc_realm_item *ri;
	struct zbc_zone_domain *d;
	struct zbc_zone *zone;
	uint64_t realm_sz;
	int i, j, dom_id, zt;
	bool zone_inact, zone_activity[ZBC_NR_ZONE_TYPES];
	bool realm_available = true;

	switch (r->type) {
	case ZBC_REALM_TYPE_NOWP:
	case ZBC_REALM_TYPE_SOBR:
	case ZBC_REALM_TYPE_SEQ_R:
	case ZBC_REALM_TYPE_SEQ_P:
		break;
	default:
		*failed = 1;
		return false;
	}

	if (r->flags & ~(ZBC_ACTV_OF_CONV | ZBC_ACTV_OF_SEQ_REQ |
			 ZBC_ACTV_OF_SEQ_PREF | ZBC_ACTV_OF_SOBR)) {
		*failed = 2;
		return false;
	}

	if (r->number != rno) {
		*failed = 3;
		return false;
	}
	if (r->number >= zdev->nr_realms) {
		*failed = 4;
		return false;
	}

	/* Cross-check the current realm type with domain type */
	dom_id = zbc_domain_id(zdev, r->type);
	if (dom_id < 0) {
		*failed = 5;
		return false;
	}
	d = &zdev->domains[dom_id];
	if (d->type != r->type) {
		*failed = 6;
		return false;
	}

	memset(zone_activity, 0, sizeof(zone_activity));
	zt = ZBC_ZONE_TYPE_CONVENTIONAL;
	for (i = 0; i < ZBC_NR_ZONE_TYPES; i++, zt++) {
		ri = &r->ri[i];
		if (!ri->length) {
			if (ri->start_lba) {
				*failed = 7;
				return false;
			}
			if (zbc_can_actv_realm_as(r, zt)) {
				*failed = 8;
				return false;
			}
			continue;
		}

		dom_id = zbc_domain_id(zdev, zt);
		if (dom_id < 0) {
			*failed = 9;
			return false;
		}
		d = &zdev->domains[dom_id];
		if (d->type != zt) {
			*failed = 10;
			return false;
		}
		/*
		 * Verify that all realm ranges lay
		 * within their respective domains.
		 */
		if (zbc_smr_domain(d)) {
			if (ri->length != zdev->nr_smr_realm_zones) {
				*failed = 11;
				return false;
			}
		} else {
			if (ri->length != zdev->nr_cmr_realm_zones) {
				*failed = 12;
				return false;
			}
		}
		if (ri->start_lba < d->start_lba) {
			*failed = 13;
			return false;
		}
		realm_sz = ((uint64_t)ri->length) << zdev->zone_log2;
		if (ri->start_lba + realm_sz - 1 > d->end_lba) {
			*failed = 14;
			return false;
		}
		if (ri->start_lba % zdev->zone_size) {
			*failed = 15;
			return false;
		}
		if (ri->start_zone >= zdev->nr_zones) {
			*failed = 16;
			return false;
		}
		if (!zbc_can_actv_realm_as(r, zt)) {
			*failed = 17;
			return false;
		}
		zone = zbc_get_zone(zdev, ri->start_lba, true);
		if (!zone) {
			*failed = 18;
			return false;
		}
		/*
		 * Find the first realm zone that is not
		 * RO/Offline and see if it is inactive.
		 */
		zone_inact = false;
		for (j = 0; j < ri->length; j++, zone++) {
			if (zbc_smr_domain(d) != zbc_zone_seq(zone)) {
				*failed = 19;
				return false;
			}
			if (!zbc_zone_rdonly(zone) &&
			    !zbc_zone_offline(zone)) {
				zone_inact = zbc_zone_inactive(zone);
				break;
			}
		}

		/* Note if ALL zones in the (domain x realm) are unavailable */
		if (j == ri->length)
			realm_available = false;

		/*
		 * Verify that the rest of the zones are consistent
		 * with the first one in terms of being active.
		 */
		for (; j < ri->length; j++, zone++) {
			if (zbc_smr_domain(d) != zbc_zone_seq(zone)) {
				*failed = 20;
				return false;
			}
			if (!zbc_zone_rdonly(zone) &&
			    !zbc_zone_offline(zone) &&
			    zone_inact != zbc_zone_inactive(zone)) {
				*failed = 21;
				return false;
			}
		}
		zone_activity[i] = !zone_inact;
	}

	/* Skip this check if all zones in the realm are offline or readonly */
	if (realm_available) {
		/*
		 * Verify that only one set of zones
		 * is actually active in this realm.
		 */
		for (i = 0, j = 0; i < ZBC_NR_ZONE_TYPES; i++)
			j += zone_activity[i];
		if (j != 1) {
			*failed = 22;
			return false;
		}
	}

	*failed = 0;
	return true;
}

/*
 * Perform core metadata checks for a Zone Domains device.
 * Make some necessary geometry calculations as we go.
 */
static bool zbc_check_meta_core_zd(struct zbc_dev *zdev, struct zbc_meta *meta,
				   unsigned int *failed)
{
	const struct zbc_dev_features *feat;
	unsigned long long phys_capacity, logical_cmr_capacity;
	unsigned long long logical_capacity;
	unsigned int nr_zones;

	if (meta->dev_type != ZBC_MT_ZONE_DOM) {
		*failed = 1;
		return false;
	}
	feat = zbc_get_dev_features(meta->dev_type, meta->dev_model);
	if (!feat) {
		*failed = 2;
		return false;
	}
	zdev->dev_feat = feat;

	zdev->meta_size = zbc_meta_size(meta->nr_realms, meta->nr_zones);
	phys_capacity = (meta->bs_size - zdev->meta_size) / meta->lba_size;
	if (meta->phys_capacity != phys_capacity) {
		*failed = 3;
		return false;
	}

	if (!meta->zone_size ||
	    meta->zone_size & (meta->zone_size - 1)) {
		*failed = 4;
		return false;
	}

	if (meta->realm_size < meta->zone_size * 2) {
		*failed = 5;
		return false;
	}

	if (meta->smr_gain <= 100) {
		*failed = 6;
		return false;
	}

	if (meta->realm_size > phys_capacity / 2) {
		*failed = 7;
		return false;
	}

	if (meta->realm_size <= meta->zone_size ||
	    meta->realm_size % meta->zone_size) {
		*failed = 8;
		return false;
	}

	zdev->nr_realms = (phys_capacity + meta->realm_size - 1) /
			   meta->realm_size;
	if (meta->nr_realms != zdev->nr_realms) {
		*failed = 9;
		return false;
	}

	logical_cmr_capacity = phys_capacity * 100 / meta->smr_gain;
	logical_capacity =
		phys_capacity + logical_cmr_capacity;

	nr_zones = logical_capacity / meta->zone_size;
	zdev->nr_conv_zones = (logical_cmr_capacity +
			       meta->zone_size - 1) / meta->zone_size;
	zdev->nr_seq_zones = (phys_capacity +
			      meta->zone_size - 1) / meta->zone_size;
	zdev->nr_open_zones = meta->nr_open_zones;
	if (zdev->nr_open_zones >= zdev->nr_seq_zones) {
		*failed = 10;
		return false;
	}

	zdev->nr_cmr_realm_zones = zdev->nr_conv_zones / zdev->nr_realms;
	zdev->nr_smr_realm_zones = zdev->nr_seq_zones / zdev->nr_realms;
	zdev->nr_conv_zones = zdev->nr_cmr_realm_zones * zdev->nr_realms;
	zdev->nr_seq_zones = zdev->nr_smr_realm_zones * zdev->nr_realms;
	if (meta->nr_conv_zones != zdev->nr_conv_zones ||
	    meta->nr_conv_zones >= nr_zones) {
		*failed = 11;
		return false;
	}
	if (!meta->nr_actv_zones) {
		*failed = 12;
		return false;
	}

	*failed = 0;
	return true;
}

/*
 * Check metadata of a Zone Domains device.
 */
static bool zbc_check_meta_zd(struct zbc_dev *zdev, struct zbc_meta *meta)
{
	unsigned int i, failed;

	/* Check main metadata fields and partially initialize zdev */
	if (!zbc_check_meta_core_zd(zdev, meta, &failed)) {
		tcmu_dev_err(zdev->dev,
			     "Failed ZD metadata check #%u\n", failed);
		return false;
	}

	/* Complete zdev initialization */
	zdev->phys_capacity = meta->phys_capacity;
	zdev->dev_model = meta->dev_model;
	zdev->realm_size = meta->realm_size;
	zdev->lba_size = meta->lba_size;
	zdev->lba_log2 = zbc_log2(zdev->lba_size);
	zdev->zone_size = meta->zone_size;
	zdev->zone_log2 = zbc_log2(zdev->zone_size);
	zdev->wp_check = meta->wp_check;
	zdev->realms_feat_set = meta->realms_feat_set;
	zdev->nr_actv_zones = meta->nr_actv_zones;
	zdev->smr_gain = meta->smr_gain;
	zdev->nr_imp_open = meta->imp_open_zones.size;
	zdev->nr_exp_open = meta->exp_open_zones.size;

	if (meta->max_activate > meta->nr_zones) {
		tcmu_dev_err(zdev->dev,
			     "MAX ACTIVATE %u in metadata > # of zones %u\n",
			     meta->max_activate, meta->nr_zones);
		zbc_unmap_meta(zdev);
		return false;
	}
	zdev->max_activate = meta->max_activate;

	if (zbc_map_meta(zdev, true))
		return false;

	/* Calculate the resulting device capacity */
	zbc_calc_total_zd_capacity(zdev);
	if (meta->nr_zones != zdev->nr_zones) {
		tcmu_dev_err(zdev->dev,
			     "Number of zones in metadata %u, calculated %u\n",
			     meta->nr_zones, zdev->nr_zones);
		zbc_unmap_meta(zdev);
		return false;
	}

	/* Check all zone domains */
	if (!zbc_check_zone_domains(zdev, &failed)) {
		tcmu_dev_err(zdev->dev,
			     "Zone domain check failure at #%u\n",
			     failed);
		zbc_unmap_meta(zdev);
		return false;
	}

	zbc_init_domain_mapping(zdev);

	/* Check all zone lists */
	if (!zbc_check_zone_lists(zdev, &failed)) {
		tcmu_dev_err(zdev->dev,
			     "Zone list corruption, failed check #%u\n",
			     failed);
		zbc_unmap_meta(zdev);
		return false;
	}

	/* Check all zone realms */
	for (i = 0; i < zdev->nr_realms; i++) {
		if (!zbc_check_zone_realm(zdev, i, &failed)) {
			tcmu_dev_err(zdev->dev,
				     "ZD realm %u failed check #%u\n",
				     i, failed);
			zbc_unmap_meta(zdev);
			return false;
		}
	}

	/* Check all zones */
	for (i = 0; i < zdev->nr_zones; i++) {
		if (!zbc_check_zone(zdev, i, &failed)) {
			tcmu_dev_err(zdev->dev,
				     "Invalid zone %u, failed check #%u\n",
				     i, failed);
			zbc_unmap_meta(zdev);
			return false;
		}
	}

	zbc_unmap_meta(zdev);

	return true;
}

/*
 * Perform core metadata checks for a zoned device.
 */
static bool zbc_check_meta_core_zoned(struct zbc_dev *zdev,
				      struct zbc_meta *meta,
				      unsigned int *failed)
{
	const struct zbc_dev_features *feat;
	unsigned long long phys_capacity;
	unsigned int nr_zones;

	if (meta->dev_type != ZBC_MT_HM_ZONED &&
	    meta->dev_type != ZBC_MT_HA_ZONED) {
		*failed = 1;
		return false;
	}
	feat = zbc_get_dev_features(meta->dev_type, meta->dev_model);
	if (!feat) {
		*failed = 2;
		return false;
	}
	zdev->dev_feat = feat;

	zdev->meta_size = zbc_meta_size(0, meta->nr_zones);
	phys_capacity = (meta->bs_size - zdev->meta_size) / meta->lba_size;
	if (meta->phys_capacity != phys_capacity) {
		*failed = 3;
		return false;
	}

	if (!meta->zone_size ||
	    meta->zone_size & (meta->zone_size - 1)) {
		*failed = 4;
		return false;
	}

	nr_zones = (meta->phys_capacity + meta->zone_size - 1) /
		   meta->zone_size;
	if (meta->nr_zones != nr_zones) {
		*failed = 5;
		return false;
	}
	if (meta->nr_conv_zones >= nr_zones) {
		*failed = 6;
		return false;
	}
	if (meta->nr_open_zones > nr_zones) {
		*failed = 7;
		return false;
	}

	*failed = 0;
	return true;
}

/*
 * Check metadata of a zoned device.
 */
static bool zbc_check_meta_zoned(struct zbc_dev *zdev, struct zbc_meta *meta)
{
	unsigned int i, failed;

	/* Check main metadata fields and partially initialize zdev */
	if (!zbc_check_meta_core_zoned(zdev, meta, &failed)) {
		tcmu_dev_err(zdev->dev,
			     "Failed zoned metadata check #%u\n", failed);
		return false;
	}

	/* Complete zdev initialization */
	zdev->dev_model = meta->dev_model;
	zdev->phys_capacity = meta->phys_capacity;
	zdev->lba_size = meta->lba_size;
	zdev->lba_log2 = zbc_log2(zdev->lba_size);
	zdev->zone_size = meta->zone_size;
	zdev->zone_log2 = zbc_log2(zdev->zone_size);
	zdev->wp_check = meta->wp_check;
	zdev->nr_zones = meta->nr_zones;
	zdev->nr_conv_zones = meta->nr_conv_zones;
	zdev->nr_open_zones = meta->nr_open_zones;
	zdev->nr_imp_open = meta->imp_open_zones.size;
	zdev->nr_exp_open = meta->exp_open_zones.size;

	/* Calculate the device capacity */
	zdev->logical_capacity = zdev->nr_zones << zdev->zone_log2;

	if (zbc_map_meta(zdev, true))
		return false;

	/* Check all zone lists */
	if (!zbc_check_zone_lists(zdev, &failed)) {
		tcmu_dev_err(zdev->dev,
			     "Zone list corruption, failed check #%u\n",
			     failed);
		zbc_unmap_meta(zdev);
		return false;
	}

	/* Check all zones */
	for (i = 0; i < zdev->nr_zones; i++) {
		if (!zbc_check_zone(zdev, i, &failed)) {
			tcmu_dev_err(zdev->dev,
				     "Invalid zone %u, failed check #%u\n",
				     i, failed);
			zbc_unmap_meta(zdev);
			return false;
		}
	}

	zbc_unmap_meta(zdev);

	return true;
}

static bool zbc_check_meta_nz(struct zbc_dev *zdev, struct zbc_meta *meta)
{
	unsigned long long phys_capacity;

	if (meta->dev_type != ZBC_MT_NON_ZONED)
		return false;
	if (meta->dev_model.nz != ZBC_MO_NZ_GENERIC)
		return false;

	zdev->meta_size = zbc_meta_size(0, 0);
	phys_capacity = (meta->bs_size - zdev->meta_size) / meta->lba_size;
	if (meta->phys_capacity != phys_capacity)
		return false;

	zdev->dev_model = meta->dev_model;
	zdev->phys_capacity = meta->phys_capacity;
	zdev->logical_capacity = zdev->phys_capacity;
	zdev->lba_size = meta->lba_size;
	zdev->lba_log2 = zbc_log2(zdev->lba_size);

	return true;
}

static bool zbc_check_meta(struct zbc_dev *zdev, struct zbc_meta *meta)
{
	switch (zdev->dev_type) {
	case ZBC_MT_NON_ZONED:
		return zbc_check_meta_nz(zdev, meta);
	case ZBC_MT_HM_ZONED:
	case ZBC_MT_HA_ZONED:
		return zbc_check_meta_zoned(zdev, meta);
	case ZBC_MT_ZONE_DOM:
		return zbc_check_meta_zd(zdev, meta);
	default:
		return false;
	}
}

/*
 * Check metadata.
 * Return true if the metadata is correct and can be used without reformatting.
 */
static bool zbc_dev_check_meta(struct tcmu_device *dev, struct stat *st)
{
	struct zbc_meta meta;
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	char *cfg_str = tcmu_get_dev_cfgstring(dev);
	ssize_t ret;

	ret = pread(zdev->fd, &meta, sizeof(struct zbc_meta), 0);
	if (ret != sizeof(struct zbc_meta))
		return false;

	if (meta.sizeof_struct_meta != sizeof(struct zbc_meta))
		return false;

	if (meta.bs_size != st->st_size)
		return false;

	if (meta.magic != META_MAGIC)
		return false;

	/*
	 * Check if the option string exactly matches
	 * with the one used when device was formatted.
	 */
	if (strncmp(cfg_str, (char *)meta.cfg_str, PATH_MAX) != 0)
		return false;

	if (meta.lba_size != 512 && meta.lba_size != 4096)
		return false;

	zdev->dev_type = meta.dev_type;

	return zbc_check_meta(zdev, &meta);
}

/*
 * Output the current configuration of a single zone realm to the log.
 */
static void zbc_print_zone_realm(struct zbc_dev *zdev, struct zbc_zone_realm *r)
{
	struct tcmu_device *dev = zdev->dev;
	struct zbc_realm_item *ri;
	int i;

	tcmu_dev_dbg(dev, "Realm #%u\n", r->number);
	tcmu_dev_dbg(dev, "  Cur Type/Domain  : %u/%u\n",
		     r->type, zbc_domain_id(zdev, r->type));
	tcmu_dev_dbg(dev, "  Flags            : 0x%x\n", r->flags);
	for (i = 0; i < ZBC_NR_ZONE_TYPES; i++) {
		ri = &r->ri[i];
		tcmu_dev_dbg(dev, "  Zone Type        : %u\n", i + 1);
		tcmu_dev_dbg(dev, "    Start LBA      : %llu\n",
			     ri->start_lba);
		tcmu_dev_dbg(dev, "    Length         : %u zones\n",
			     ri->length);
		tcmu_dev_dbg(dev, "    Start Zone     : %u\n",
			     ri->start_zone);
	}
}

static inline void zbc_print_realms(struct zbc_dev *zdev)
{
	struct zbc_zone_realm *r = zdev->realms;
	int i;

	for (i = 0; i < zdev->nr_realms; i++, r++)
		zbc_print_zone_realm(zdev, r);
}

/*
 * Output the current configuration of a Zone Domains device.
 */
static void zbc_print_config_zd(struct zbc_dev *zdev)
{
	struct tcmu_device *dev = zdev->dev;
	struct zbc_zone_domain *d = zdev->domains;
	int i;

	tcmu_dev_dbg(dev, "Device model %u : %s\n", zdev->dev_model.zd,
		     zdev->dev_feat->opt_name);
	tcmu_dev_dbg(dev, "%u zone realms of %llu MiB\n",
		     zdev->nr_realms,
		     (zdev->realm_size * zdev->lba_size) / 1048576);
	tcmu_dev_dbg(dev, "%u CMR zones/realm, %u SMR zones/realm\n",
		     zdev->nr_cmr_realm_zones, zdev->nr_smr_realm_zones);

	tcmu_dev_dbg(dev, "Zone domains:\n");
	for (i = 0; i < zdev->nr_domains; i++, d++) {
		if (i > 0 && d->start_lba > (d - 1)->end_lba + 1) {
			tcmu_dev_dbg(dev,
			    "GAP %016llu..%016llu, %llu zones\n",
			    (d - 1)->end_lba + 1, d->start_lba - 1,
			    (d->start_lba - 1 - (d - 1)->end_lba + 1) /
			    zdev->zone_size);
		}
		tcmu_dev_dbg(dev,
		    "%u:  %016llu..%016llu, type 0x%x, %u zones, flags 0x%x\n",
		    i, d->start_lba, d->end_lba, d->type,
		    d->nr_zones, d->flags);
	}
	tcmu_dev_dbg(dev, "-------------\n");

	tcmu_dev_dbg(dev,
		     "%llu logical blocks of %zu B (%.03F GB)\n",
		     zdev->logical_capacity, zdev->lba_size,
		     (double)(zdev->logical_capacity * zdev->lba_size) /
			     1000000000);
	tcmu_dev_dbg(dev,
		     "%llu CMR logical blocks, %llu SMR logical blocks\n",
		     zdev->logical_cmr_capacity,
		     zdev->logical_smr_capacity);
	tcmu_dev_dbg(dev,
		     "%llu 512-bytes sectors (%llu CMR + %llu SMR)\n",
		     (zdev->logical_capacity * zdev->lba_size) >> 9,
		     (zdev->logical_cmr_capacity * zdev->lba_size) >> 9,
		     (zdev->logical_smr_capacity * zdev->lba_size) >> 9);

	tcmu_dev_dbg(dev,
		     "%u zones of %zu 512-bytes sectors (%zu LBAs)\n",
		     zdev->nr_zones, (zdev->zone_size * zdev->lba_size) >> 9,
		     zdev->zone_size);
	tcmu_dev_dbg(dev,
		     "%u conventional zones, %u sequential zones per domain\n",
		     zdev->nr_conv_zones, zdev->nr_seq_zones);

	tcmu_dev_dbg(dev,
		     "Maximum %u open sequential write required zones\n",
		     zdev->nr_open_zones);
}

/*
 * Output the current configuration of a zoned device.
 */
static void zbc_print_config_zoned(struct zbc_dev *zdev)
{
	struct tcmu_device *dev = zdev->dev;

	tcmu_dev_dbg(dev, "Device model %u : %s\n", zdev->dev_model.smr,
		     zdev->dev_feat->opt_name);
	tcmu_dev_dbg(dev,
		     "%llu 512-bytes sectors\n",
		     (zdev->logical_capacity * zdev->lba_size) >> 9);
	tcmu_dev_dbg(dev,
		     "%llu logical blocks of %u B (%.03F GB)\n",
		     (unsigned long long) zdev->logical_capacity,
		     (unsigned int) zdev->lba_size,
		     (double)(zdev->logical_capacity * zdev->lba_size) /
			     1000000000);
	tcmu_dev_dbg(dev,
		     "%u zones of %zu 512-bytes sectors (%zu LBAs)\n",
		     zdev->nr_zones, (zdev->zone_size * zdev->lba_size) >> 9,
		     zdev->zone_size);
	tcmu_dev_dbg(dev,
		     "%u conventional zones\n",
		     zdev->nr_conv_zones);
	if (zbc_mt_hm(zdev)) {
		tcmu_dev_dbg(dev,
			     "Maximum %u open seq write required zones\n",
			     zdev->nr_open_zones);
	} else {
		char swpz[] = "sequential write preferred zones";

		tcmu_dev_dbg(dev,
			"Optimal open %s: %u\n",
			swpz, zdev->nr_open_zones);
		tcmu_dev_dbg(dev,
			"Optimal non-sequentially written %s: %u\n",
			swpz, zdev->nr_open_zones);
	}
}

/*
 * Output the current configuration of a non-zoned (PMR) device.
 */
static void zbc_print_config_nz(struct zbc_dev *zdev)
{
	struct tcmu_device *dev = zdev->dev;

	tcmu_dev_dbg(dev,
		     "%llu logical blocks of %u B (%.03F GB)\n",
		     (unsigned long long) zdev->logical_capacity,
		     (unsigned int) zdev->lba_size,
		     (double)(zdev->logical_capacity * zdev->lba_size) /
			     1000000000);
	tcmu_dev_dbg(dev,
		     "%llu 512-bytes sectors\n",
		     (zdev->logical_capacity * zdev->lba_size) >> 9);
}

/*
 * Set the write pointer of a zone during format.
 * Zones in certain condition need to be added to the list of active zones.
 */
static void zbc_set_initial_wp(struct zbc_dev *zdev, struct zbc_zone *zone)
{
	switch (zone->cond) {
	case ZBC_ZONE_COND_EMPTY:
		zone->wp = zone->start;
		zbc_add_zone_tail(zdev, zdev->seq_active_zones, zone);
		break;
	case ZBC_ZONE_COND_FULL:
		if (zbc_zone_seq(zone))
			zone->wp = zone->start + zone->len;
		else
			zone->wp = ZBC_NO_WP;
		zbc_add_zone_tail(zdev, zdev->seq_active_zones, zone);
		break;
	case ZBC_ZONE_COND_INACTIVE:
	case ZBC_ZONE_COND_NOT_WP:
	case ZBC_ZONE_COND_READONLY:
	case ZBC_ZONE_COND_OFFLINE:
		zone->wp = ZBC_NO_WP;
		break;
	case ZBC_ZONE_COND_CLOSED:
	case ZBC_ZONE_COND_IMP_OPEN:
	case ZBC_ZONE_COND_EXP_OPEN:
	default:
		tcmu_dev_err(zdev->dev,
			     "Zone %llu initialized in condition 0x%x\n",
			     zone->start, zone->cond);
	}
}

/*
 * Initialize zones of realm "r" in domain "d".
 * When this function is called, all the domain zones already have
 * the required type and OFFLINE condition. All that remains to be
 * done is to set the appropriate zone condition to all realm zones
 * and, if needed, add them to an appropriate zone list.
 */
static int zbc_init_zones_zd(struct zbc_dev *zdev,
			     struct zbc_zone_realm *r,
			     struct zbc_zone_domain *d)
{
	const struct zbc_dev_features *feat = zdev->dev_feat;
	struct zbc_realm_item *ri;
	struct zbc_zone *zone;
	unsigned long long lba;
	unsigned int i, nr_zones, cond;

	/* All but one set of zones must be in inactive condition */
	cond = ZBC_ZONE_COND_INACTIVE;
	if (zbc_smr_domain(d)) {
		if (d->type == feat->initial_smr_type && zbc_realm_seq(r))
			cond = feat->initial_smr_cond;
	} else {
		if (d->type == feat->initial_cmr_type && !zbc_realm_seq(r))
			cond = feat->initial_cmr_cond;
	}

	ri = zbc_get_realm_item(r, d->type);
	lba = ri->start_lba;
	nr_zones = ri->length;
	zone = zbc_get_zone(zdev, lba, false);
	if (!zone) {
		tcmu_dev_err(zdev->dev,
			     "Can't get start zone %llu\n", lba);
		return 1;
	}
	ri->start_zone = zone - zdev->zones;
	for (i = 0; i < nr_zones; i++, zone++) {
		zone->type = d->type;
		zone->cond = cond;
		if (cond == ZBC_ZONE_COND_EMPTY)
			zdev->nr_empty_zones++;
		zbc_set_initial_wp(zdev, zone);	/* Put onto zone list */
	}

	return 0;
}

static int
zbc_inject_zone_cond_zoned(struct zbc_dev *zdev, unsigned int zone_idx,
			   enum zbc_zone_cond cond, unsigned int nr_zones)
{
	struct zbc_zone *zone;
	uint64_t start_lba;
	int j;

	start_lba = zone_idx * zdev->zone_size;
	zone = zbc_get_zone(zdev, start_lba, false);
	if (!zone) {
		tcmu_dev_err(zdev->dev,
				"Can't locate zone %"PRIu64"\n",
				start_lba);
		return 1;
	}
	if (zone - zdev->zones > zdev->nr_zones - nr_zones) {
		tcmu_dev_err(zdev->dev,
			"%u zone(s) at %zu (%"PRIu64") being injected too high",
			nr_zones, zone - zdev->zones, start_lba);
		return 1;
	}
	for (j = 0; j < nr_zones; j++, zone++) {
		if (zbc_zone_empty(zone) && cond != ZBC_ZONE_COND_EMPTY)
			zdev->nr_empty_zones--;

		zbc_unlink_zone(zdev, zone);
		zone->cond = cond;
		zbc_set_initial_wp(zdev, zone);
	}

	return 0;
}

static void zbc_init_zones_zoned(struct zbc_dev *zdev,
				 enum zbc_device_type dev_type,
				 enum zbc_mutation_opt_smr model)
{
	struct zbc_zone *zone = zdev->zones;
	const struct zbc_dev_features *feat = zdev->dev_feat;
	unsigned long long lba = 0;
	unsigned int i, zone_type, nr_convz;

	nr_convz = zdev->nr_conv_zones;
	if (model == ZBC_MO_SMR_2PCNT_BT && nr_convz > 0)
		nr_convz--;
	if (dev_type == ZBC_MT_HA_ZONED)
		zone_type = ZBC_ZONE_TYPE_SEQWRITE_PREF;
	else
		zone_type = ZBC_ZONE_TYPE_SEQWRITE_REQ;

	for (i = 0; i < zdev->nr_zones; i++, zone++) {
		zone->start = lba;
		zone->prev = zone->next = 0;
		if (zone->start + zdev->zone_size > zdev->logical_capacity)
			zone->len = zdev->logical_capacity - zone->start;
		else
			zone->len = zdev->zone_size;
		if (i < nr_convz ||
		    (model == ZBC_MO_SMR_2PCNT_BT &&
		     i == zdev->nr_zones - 1)) {
			zone->type = ZBC_ZONE_TYPE_CONVENTIONAL;
			zone->cond = ZBC_ZONE_COND_NOT_WP;
		} else {
			zone->type = zone_type;
			zone->cond = ZBC_ZONE_COND_EMPTY;
			zdev->nr_empty_zones++;
		}
		zbc_set_initial_wp(zdev, zone);

		lba += zone->len;
	}

	/* If needed, mark some zones read-only */
	if (feat->nr_rdonly_zones) {
		unsigned int zone_idx = feat->rdonly_zone_offset;

		if (zone_idx + feat->nr_rdonly_zones > zdev->nr_conv_zones)
			tcmu_dev_err(zdev->dev,
				     "Ignore bad CMR rdonly offset/len %"PRIu64
				     "/%zu\n",
				     feat->rdonly_zone_offset,
				     feat->nr_rdonly_zones);
		else
			zbc_inject_zone_cond_zoned(zdev, zone_idx,
						   ZBC_ZONE_COND_READONLY,
						   feat->nr_rdonly_zones);
	}

	/* If needed, mark some zones offline */
	if (feat->nr_offline_zones) {
		unsigned int zone_idx = feat->offline_zone_offset;

		if (zone_idx + feat->nr_offline_zones > zdev->nr_conv_zones)
			tcmu_dev_err(zdev->dev,
				     "Ignore bad CMR offline offset/len %zu/%zu\n",
				     feat->offline_zone_offset,
				     feat->nr_offline_zones);
		else
			zbc_inject_zone_cond_zoned(zdev, zone_idx,
						   ZBC_ZONE_COND_OFFLINE,
						   feat->nr_offline_zones);
	}

	zdev->min_empty_zones = zdev->nr_empty_zones;
}

/*
 * Initialize a single zone domain.
 */
static uint64_t zbc_init_domain(struct zbc_dev *zdev, struct zbc_zone_domain *d,
				uint64_t start_lba, uint8_t flags)
{
	d->start_lba = start_lba;
	if (flags & ZBC_DFLG_SMR)
		start_lba += zdev->logical_smr_capacity;
	else
		start_lba += zdev->logical_cmr_capacity;
	d->end_lba = start_lba - 1;
	d->nr_zones = (start_lba - d->start_lba) / zdev->zone_size;
	d->flags = flags;

	return start_lba;
}

/*
 * Initialize the domain array of a Zone Domains device.
 */
static void zbc_init_zone_domains(struct zbc_dev *zdev, struct zbc_meta *meta)
{
	const struct zbc_dev_features *feat = zdev->dev_feat;
	struct zbc_zone_domain *d = meta->domains;
	struct zbc_zone *zone = zdev->zones;
	uint64_t start_lba = 0LL;
	unsigned int i, nr_domains = 0;

	memset(meta->domains, 0, sizeof(meta->domains));
	if (feat->actv_of_sobr) {
		d->type = ZBC_ZONE_TYPE_SEQ_OR_BEF_REQ;
		start_lba = zbc_init_domain(zdev, d, start_lba, 0) +
			    feat->domain_gap * zdev->zone_size;
		d++;
		nr_domains++;
	}
	if (feat->actv_of_conv) {
		d->type = ZBC_ZONE_TYPE_CONVENTIONAL;
		start_lba = zbc_init_domain(zdev, d, start_lba, 0) +
			    feat->domain_gap * zdev->zone_size;
		d++;
		nr_domains++;
	}
	if (feat->actv_of_seq_req) {
		d->type = ZBC_ZONE_TYPE_SEQWRITE_REQ;
		start_lba = zbc_init_domain(zdev, d, start_lba, ZBC_DFLG_SMR) +
			    feat->domain_gap * zdev->zone_size;
		d++;
		nr_domains++;
	}
	if (feat->actv_of_seq_pref) {
		d->type = ZBC_ZONE_TYPE_SEQWRITE_PREF;
		zbc_init_domain(zdev, d, start_lba, ZBC_DFLG_SMR);
		nr_domains++;
	}

	zdev->domains = meta->domains;
	zdev->nr_domains = nr_domains;

	/* Initialize the whole range of zones to have GAP type */
	start_lba = 0LL;
	for (i = 0; i < zdev->nr_zones; i++, zone++) {
		zone->start = start_lba;
		zone->len = zdev->zone_size;
		zone->type = ZBC_ZONE_TYPE_GAP;
		zone->cond = ZBC_ZONE_COND_NOT_WP;
		zone->prev = zone->next = 0;
		zone->wp = ZBC_NO_WP;

		start_lba += zone->len;
	}
}

/*
 * Given the start zone index in the first CMR domain and the number of zones,
 * assign the specified condition to this zone range in all domains.
 */
static int zbc_inject_zone_cond(struct zbc_dev *zdev, unsigned int zone_idx,
				enum zbc_zone_cond cond, unsigned int nr_zones)
{
	struct zbc_zone_domain *d = zdev->domains;
	struct zbc_zone *zone;
	uint64_t start_lba;
	unsigned int smr_zone_idx, nrz, smr_nrz;
	int i, j;

	smr_zone_idx = zone_idx * zdev->smr_gain / 100;
	smr_nrz = nr_zones * zdev->smr_gain / 100;

	for (i = 0; i < zdev->nr_domains; i++, d++) {
		start_lba = d->start_lba;
		if (zbc_smr_domain(d)) {
			start_lba += smr_zone_idx * zdev->zone_size;
			nrz = smr_nrz;
		} else {
			start_lba += zone_idx * zdev->zone_size;
			nrz = nr_zones;
		}
		zone = zbc_get_zone(zdev, start_lba, false);
		if (!zone) {
			tcmu_dev_err(zdev->dev, "Can't locate zone %"PRIu64
						" in domain %u\n",
				     start_lba, i);
			return 1;
		}
		if (zone - zdev->zones > zdev->nr_zones - nrz) {
			tcmu_dev_err(zdev->dev,
				     "Zone %zu (%"PRIu64") injected too high",
				     zone - zdev->zones, start_lba);
			return 1;
		}
		for (j = 0; j < nrz; j++, zone++) {
			if (zbc_zone_empty(zone) &&
			    cond != ZBC_ZONE_COND_EMPTY)
				zdev->nr_empty_zones--;

			zbc_unlink_zone(zdev, zone);
			zone->cond = cond;
			zbc_set_initial_wp(zdev, zone);
		}
	}

	return 0;
}

/*
 * Trim potential gap zones from the top of the LBA range.
 */
static void zbc_trim_gap_zones(struct zbc_dev *zdev)
{
	struct zbc_zone *zone;
	unsigned int i, to_trim = 0;

	if (!zdev->nr_zones)
		return;
	zone = &zdev->zones[zdev->nr_zones - 1];
	for (i = zdev->nr_zones; i > 0; i--, zone--) {
		if (!zbc_zone_gap(zone))
			break;
		to_trim++;
	}

	zdev->nr_zones -= to_trim;
	zdev->logical_capacity -= to_trim * zdev->zone_size;
}

/*
 * Initialize realms of a Zone Domains device.
 */
static int zbc_init_zone_realms(struct zbc_dev *zdev)
{
	const struct zbc_dev_features *feat = zdev->dev_feat;
	struct zbc_zone_domain *d = zdev->domains;
	struct zbc_zone_realm *r = zdev->realms;
	struct zbc_realm_item *ri;
	uint64_t cr_sz, sr_sz, rsz;
	unsigned int i, j, k, rl, cmr_only_bcnt, cob;
	unsigned int cmr_only_tcnt, zone_idx;
	bool add_type;

	cmr_only_bcnt = feat->nr_bot_cmr;
	cmr_only_tcnt = zdev->nr_realms - feat->nr_top_cmr - 1;

	/* Initialize realm IDs and currently active zone types */
	r = zdev->realms;
	for (i = 0; i < zdev->nr_realms; i++, r++) {
		r->number = i;
		d = zdev->domains;
		if (zbc_smr_domain(d))
			r->type = feat->initial_smr_type;
		else
			r->type = feat->initial_cmr_type;
	}

	cr_sz = ((uint64_t)zdev->nr_cmr_realm_zones) << zdev->zone_log2;
	sr_sz = ((uint64_t)zdev->nr_smr_realm_zones) << zdev->zone_log2;

	/*
	 * Initialize realm starting LBAs and lengths for every supported
	 * zone type. Set activation flags for SMR and CMR zone types.
	 */
	for (j = 0, d = zdev->domains; j < zdev->nr_domains; j++, d++) {
		cob = cmr_only_bcnt;
		r = zdev->realms;
		for (i = 0, k = 0; i < zdev->nr_realms; i++, r++) {
			ri = zbc_get_realm_item(r, d->type);
			if (zbc_smr_domain(d)) {
				add_type = false;
				if (cob)
					cob--;
				else if (i <= cmr_only_tcnt) {
					add_type = true;
					rsz = sr_sz;
				}
				rl = zdev->nr_smr_realm_zones;
			} else {
				add_type = true;
				rsz = cr_sz;
				rl = zdev->nr_cmr_realm_zones;
			}
			if (add_type) {
				ri->start_lba = d->start_lba + k * rsz;
				ri->length = rl;
				r->flags |= 1 << (d->type - 1);
				k++;
			} else {
				d->end_lba -= rl * zdev->zone_size;
				d->nr_zones -= rl;
				continue;
			}

			if (zbc_init_zones_zd(zdev, r, d))
				return 1;
		}
	}

	zbc_trim_gap_zones(zdev);

	/* If needed, mark some zones read-only */
	if (feat->nr_rdonly_zones) {
		zone_idx = feat->rdonly_zone_offset;
		if (zone_idx + feat->nr_rdonly_zones >= zdev->nr_conv_zones) {
			tcmu_dev_err(zdev->dev,
				     "Bad CMR rdonly offset/length %"PRIu64
				     "/%zu\n",
				     feat->rdonly_zone_offset,
				     feat->nr_rdonly_zones);
			return 1;
		}
		if (zbc_inject_zone_cond(zdev, zone_idx,
					 ZBC_ZONE_COND_READONLY,
					 feat->nr_rdonly_zones))
			return 1;
	}

	/* If needed, mark some zones offline */
	if (feat->nr_offline_zones) {
		zone_idx = feat->offline_zone_offset;
		if (zone_idx + feat->nr_offline_zones >= zdev->nr_conv_zones) {
			tcmu_dev_err(zdev->dev,
				     "Bad SMR offline offset/length %zu/%zu\n",
				     feat->offline_zone_offset,
				     feat->nr_offline_zones);
			return 1;
		}
		if (zbc_inject_zone_cond(zdev, zone_idx,
					 ZBC_ZONE_COND_OFFLINE,
					 feat->nr_offline_zones))
			return 1;
	}

	zdev->min_empty_zones = zdev->nr_empty_zones;

	return 0;
}

/*
 * Write the metadata portion that is common for all device types.
 */
static void zbc_write_meta_common(struct zbc_dev *zdev, struct zbc_meta *meta)
{
	meta->sizeof_struct_meta = sizeof(struct zbc_meta);
	meta->time_create = time(NULL);

	meta->dev_type = zdev->dev_type;
	meta->dev_model = zdev->dev_model;
	meta->bs_size = zdev->bs_size;
	meta->magic = META_MAGIC;
	strncpy((char *)meta->cfg_str,
		tcmu_get_dev_cfgstring(zdev->dev), PATH_MAX);

	meta->phys_capacity = zdev->phys_capacity;
	meta->lba_size = zdev->lba_size;
}

/*
 * Format metadata to become a Zone Domains device.
 */
static int zbc_format_meta_zd(struct zbc_dev *zdev, struct zbc_dev_config *cfg)
{
	struct tcmu_device *dev = zdev->dev;
	struct zbc_meta *meta;
	int ret;

	zdev->lba_size = cfg->lba_size;
	zdev->lba_log2 = zbc_log2(zdev->lba_size);
	zdev->phys_capacity = cfg->phys_capacity / zdev->lba_size;
	zdev->zone_size = cfg->zone_size / zdev->lba_size;
	zdev->zone_log2 = zbc_log2(zdev->zone_size);
	zdev->realm_size = cfg->realm_size / zdev->lba_size;
	zdev->smr_gain = cfg->smr_gain;

	if (zdev->realm_size > zdev->phys_capacity / 2) {
		tcmu_dev_err(dev,
			     "Invalid realm/capacity size (%llu / %llu)\n",
			     zdev->realm_size, zdev->phys_capacity);
		return -ENOSPC;
	}

	if (zdev->realm_size < (zdev->zone_size * 2) ||
	    zdev->realm_size % zdev->zone_size) {
		tcmu_dev_err(dev, "Invalid realm/zone size (%llu / %zu\n)",
			     zdev->realm_size, zdev->zone_size);
		return -ENOSPC;
	}

	zdev->nr_realms = (zdev->phys_capacity + zdev->realm_size - 1) /
			  zdev->realm_size;
	zdev->phys_capacity = zdev->nr_realms * zdev->realm_size;
	zdev->logical_smr_capacity = zdev->phys_capacity;
	zdev->logical_cmr_capacity =
		zdev->logical_smr_capacity * 100 / zdev->smr_gain;

	zdev->nr_conv_zones = (zdev->logical_cmr_capacity +
			       zdev->zone_size - 1) >> zdev->zone_log2;
	zdev->nr_seq_zones = (zdev->logical_smr_capacity +
			      zdev->zone_size - 1) >> zdev->zone_log2;

	zdev->nr_cmr_realm_zones = zdev->nr_conv_zones / zdev->nr_realms;
	zdev->nr_smr_realm_zones = zdev->nr_seq_zones / zdev->nr_realms;
	zdev->nr_conv_zones = zdev->nr_cmr_realm_zones * zdev->nr_realms;
	zdev->nr_seq_zones = zdev->nr_smr_realm_zones * zdev->nr_realms;
	zdev->nr_actv_zones = zdev->nr_cmr_realm_zones;

	zbc_calc_total_zd_capacity(zdev);

	zdev->nr_open_zones = cfg->open_num;
	if (zdev->nr_open_zones >= zdev->nr_seq_zones / 2) {
		zdev->nr_open_zones = zdev->nr_seq_zones / 2;
		if (!zdev->nr_open_zones)
			zdev->nr_open_zones = 1;
	}

	zdev->nr_imp_open = 0;
	zdev->nr_exp_open = 0;

	zdev->max_activate = cfg->max_activate;
	zdev->realms_feat_set = cfg->realms_feat_set;

	/* Command line overrides the URSWRZ setting in feature profile */
	if (cfg->wp_check != ZBC_CONF_WP_CHECK_NOT_SET)
		zdev->wp_check = cfg->wp_check;
	else
		zdev->wp_check = zdev->dev_feat->initial_wp_check;

	tcmu_dev_dbg(dev, "Formatting DH-SMR metadata...\n");
	tcmu_dev_dbg(dev, "  Device model %u : %s\n", zdev->dev_model.zd,
		     zdev->dev_feat->opt_name);
	tcmu_dev_dbg(dev, "  LBA size: %zu B\n", cfg->lba_size);
	tcmu_dev_dbg(dev, "  %u realms of %llu MiB\n",
		     zdev->nr_realms, cfg->realm_size / 1024 / 1024);
	tcmu_dev_dbg(dev, "  %u zones of %zu MiB\n",
		     zdev->nr_zones, cfg->zone_size / 1024 / 1024);
	tcmu_dev_dbg(dev, "  %u conv zones, %u seq zones\n",
		     zdev->nr_conv_zones, zdev->nr_seq_zones);
	tcmu_dev_dbg(dev, "  %u max open zones\n", cfg->open_num);
	if (zdev->max_activate)
		tcmu_dev_dbg(dev, "  %u max zones to activate at once\n",
			     zdev->max_activate);
	tcmu_dev_dbg(dev, "  Unrestricted reads : %s\n",
		     cfg->wp_check ? "n" : "y");
	tcmu_dev_dbg(dev, "  Realms command set support : %s\n",
		     cfg->realms_feat_set ? "y" : "n");
	if (cfg->realms_feat_set)
		tcmu_dev_dbg(dev, "  REPORT REALMS command support : %s\n",
			     zdev->dev_feat->no_report_realms ? "n" : "y");

	/* Truncate file */
	zdev->meta_size = zbc_meta_size(zdev->nr_realms, zdev->nr_zones);
	zdev->bs_size = zdev->meta_size + zdev->phys_capacity * zdev->lba_size;
	ret = ftruncate(zdev->fd, zdev->bs_size);
	if (ret < 0) {
		ret = -errno;
		tcmu_dev_err(dev, "Truncate %s failed (%m)\n", cfg->path);
		return ret;
	}

	/* Mmap metadata */
	ret = zbc_map_meta(zdev, false);
	if (ret)
		return ret;

	/* Write metadata */
	meta = zdev->meta;
	memset(meta, 0, zdev->meta_size);
	zbc_write_meta_common(zdev, meta);

	zbc_init_zone_domains(zdev, meta);

	meta->zone_size = zdev->zone_size;
	meta->nr_zones = zdev->nr_zones;
	meta->nr_conv_zones = zdev->nr_conv_zones;
	meta->nr_open_zones = zdev->nr_open_zones;
	meta->wp_check = zdev->wp_check;
	meta->realms_feat_set = zdev->realms_feat_set;

	meta->realm_size = zdev->realm_size;
	meta->nr_realms = zdev->nr_realms;
	meta->smr_gain = zdev->smr_gain;
	meta->max_activate = zdev->max_activate;
	meta->nr_actv_zones = zdev->nr_actv_zones;

	/* Init zone lists */
	zbc_init_zone_list(zdev->imp_open_zones);
	zbc_init_zone_list(zdev->exp_open_zones);
	zbc_init_zone_list(zdev->closed_zones);
	zbc_init_zone_list(zdev->seq_active_zones);

	/* Initialize all realms and zones */
	ret = zbc_init_zone_realms(zdev);
	if (ret) {
		tcmu_dev_err(dev, "Can't init zone realms\n");
		zbc_unmap_meta(zdev);
		return ret;
	}

	zbc_init_domain_mapping(zdev);

	ret = zbc_flush_meta(zdev);
	if (ret) {
		zbc_unmap_meta(zdev);
		return ret;
	}

	return 0;
}

/*
 * Format metadata to become a zoned device.
 */
static int zbc_format_meta_zoned(struct zbc_dev *zdev,
				 struct zbc_dev_config *cfg)
{
	struct tcmu_device *dev = zdev->dev;
	struct zbc_meta *meta;
	unsigned int nr_seq_zones;
	unsigned int max_rdonly_zone, max_offline_zone, max_faulty_zone;
	int ret;

	zdev->lba_size = cfg->lba_size;
	zdev->lba_log2 = zbc_log2(zdev->lba_size);
	zdev->phys_capacity = cfg->phys_capacity / zdev->lba_size;
	zdev->zone_size = cfg->zone_size / zdev->lba_size;
	zdev->zone_log2 = zbc_log2(zdev->zone_size);

	zdev->nr_zones = (zdev->phys_capacity + zdev->zone_size - 1) >>
			 zdev->zone_log2;
	if (cfg->mutating) {
		switch (zdev->dev_model.smr) {
		case ZBC_MO_SMR_1PCNT_B:
			/* 1% of the capacity as conventional zones */
			zdev->nr_conv_zones = zdev->nr_zones / 100;
			if (!zdev->nr_conv_zones)
				zdev->nr_conv_zones = 1;
			break;

		case ZBC_MO_SMR_FAULTY:
			zdev->nr_conv_zones = zdev->nr_zones / 100;
			/* Enough conventional zones to set the faulty ones? */
			max_rdonly_zone = zdev->dev_feat->rdonly_zone_offset +
					  zdev->dev_feat->nr_rdonly_zones;
			max_offline_zone = zdev->dev_feat->offline_zone_offset +
					   zdev->dev_feat->nr_offline_zones;
			max_faulty_zone = max_rdonly_zone > max_offline_zone ?
					  max_rdonly_zone : max_offline_zone;
			if (max_faulty_zone > zdev->nr_zones) {
				tcmu_dev_err(dev,
					"Not enough zones to set up FAULTY\n");
				return -ENOSPC;
			}
			if (zdev->nr_conv_zones < max_faulty_zone)
				zdev->nr_conv_zones = max_faulty_zone;
			break;

		case ZBC_MO_SMR_2PCNT_BT:
			/* 2% of the capacity as conventional zones */
			zdev->nr_conv_zones = zdev->nr_zones / 50;
			if (!zdev->nr_conv_zones)
				zdev->nr_conv_zones = 1;
			/* Add the top CMR zone */
			zdev->nr_conv_zones++;
			break;

		default:
			zdev->nr_conv_zones = 0;
		}
	} else if (cfg->conv_num == ZBC_CONF_DEFAULT_CONV_NUM) {
		/* Default: 1% of the capacity as conventional zones */
		zdev->nr_conv_zones = zdev->nr_zones / 100;
		if (!zdev->nr_conv_zones)
			zdev->nr_conv_zones = 1;
	} else {
		zdev->nr_conv_zones = cfg->conv_num;
		if (zdev->nr_conv_zones >= zdev->nr_zones) {
			tcmu_dev_err(dev, "Too many conventional zones\n");
			return -ENOSPC;
		}
	}

	zdev->logical_capacity = zdev->nr_zones << zdev->zone_log2;
	zdev->nr_open_zones = cfg->open_num;
	nr_seq_zones = zdev->nr_zones - zdev->nr_conv_zones;
	if (zdev->nr_open_zones >= nr_seq_zones / 2) {
		zdev->nr_open_zones = nr_seq_zones / 2;
		if (!zdev->nr_open_zones)
			zdev->nr_open_zones = 1;
	}

	zdev->nr_imp_open = 0;
	zdev->nr_exp_open = 0;

	/* Command line overrides the URSWRZ setting in feature profile */
	if (cfg->wp_check != ZBC_CONF_WP_CHECK_NOT_SET)
		zdev->wp_check = cfg->wp_check;
	else
		zdev->wp_check = zdev->dev_feat->initial_wp_check;

	tcmu_dev_dbg(dev, "Formatting SMR metadata...\n");
	tcmu_dev_dbg(dev, "Device model %u : %s\n", zdev->dev_model.smr,
		     zdev->dev_feat->opt_name);
	tcmu_dev_dbg(dev, "  Zone model: %s\n",
		     zdev->dev_type == ZBC_MT_HM_ZONED ? "HM" : "HA");
	tcmu_dev_dbg(dev, "  LBA size: %zu B\n", cfg->lba_size);
	tcmu_dev_dbg(dev, "  %u zones of %zu MiB\n",
		     zdev->nr_zones, cfg->zone_size / 1024 / 1024);
	tcmu_dev_dbg(dev, "  Number of conventional zones: %u\n",
		     zdev->nr_conv_zones);
	tcmu_dev_dbg(dev, "  Number of open zones: %u\n", cfg->open_num);

	/* Truncate file */
	zdev->meta_size = zbc_meta_size(0, zdev->nr_zones);
	zdev->bs_size = zdev->meta_size + zdev->phys_capacity * zdev->lba_size;
	ret = ftruncate(zdev->fd, zdev->bs_size);
	if (ret < 0) {
		ret = -errno;
		tcmu_dev_err(dev, "Truncate %s failed (%m)\n", cfg->path);
		return ret;
	}

	/* Mmap metadata */
	ret = zbc_map_meta(zdev, false);
	if (ret)
		return ret;

	/* Write metadata */
	meta = zdev->meta;
	memset(meta, 0, zdev->meta_size);
	zbc_write_meta_common(zdev, meta);

	meta->zone_size = zdev->zone_size;
	meta->nr_zones = zdev->nr_zones;
	meta->nr_conv_zones = zdev->nr_conv_zones;
	meta->nr_open_zones = zdev->nr_open_zones;
	meta->wp_check = zdev->wp_check;

	/* Init zone lists */
	zbc_init_zone_list(zdev->imp_open_zones);
	zbc_init_zone_list(zdev->exp_open_zones);
	zbc_init_zone_list(zdev->closed_zones);
	zbc_init_zone_list(zdev->seq_active_zones);

	/* Initialize zones */
	zbc_init_zones_zoned(zdev, meta->dev_type, meta->dev_model.smr);

	ret = zbc_flush_meta(zdev);
	if (ret) {
		zbc_unmap_meta(zdev);
		return ret;
	}

	return 0;
}

/*
 * Format metadata for a legacy non-zoned drive.
 */
static int zbc_format_meta_nz(struct zbc_dev *zdev, struct zbc_dev_config *cfg)
{
	struct zbc_meta *meta;
	int ret;

	zdev->lba_size = cfg->lba_size;
	zdev->lba_log2 = zbc_log2(zdev->lba_size);
	zdev->phys_capacity = cfg->phys_capacity / zdev->lba_size;
	zdev->logical_capacity = zdev->phys_capacity;

	tcmu_dev_dbg(zdev->dev, "Formatting PMR metadata...\n");
	tcmu_dev_dbg(zdev->dev, "  LBA size: %zu B\n",
		     cfg->lba_size);

	/* Truncate file */
	zdev->meta_size = zbc_meta_size(0, 0);
	zdev->bs_size = zdev->meta_size + zdev->phys_capacity * zdev->lba_size;
	ret = ftruncate(zdev->fd, zdev->bs_size);
	if (ret < 0) {
		ret = -errno;
		tcmu_dev_err(zdev->dev, "Truncate %s failed (%m)\n",
			     cfg->path);
		return ret;
	}

	/* Mmap metadata */
	ret = zbc_map_meta(zdev, false);
	if (ret)
		return ret;

	/* Write metadata */
	meta = zdev->meta;
	memset(meta, 0, zdev->meta_size);
	zbc_write_meta_common(zdev, meta);

	ret = zbc_flush_meta(zdev);
	if (ret) {
		zbc_unmap_meta(zdev);
		return ret;
	}

	return 0;
}

/*
 * Format metadata.
 */
static int zbc_format_meta(struct zbc_dev *zdev)
{
	struct zbc_dev_config *cfg = &zdev->cfg;
	const struct zbc_dev_features *feat;

	if (!cfg->mutating) {
		zdev->dev_type = cfg->dev_type;
		zdev->dev_model = cfg->dev_model;
	}

	feat = zbc_get_dev_features(zdev->dev_type, zdev->dev_model);
	if (!feat) {
		tcmu_dev_err(zdev->dev,
			     "Unsupported device type %u/model %u\n",
			     zdev->dev_type, zdev->dev_model.zd);
		return false;
	}
	zdev->dev_feat = feat;

	tcmu_dev_warn(zdev->dev, "Formatting metadata as type %u/model %u\n",
		      zdev->dev_type, zdev->dev_model.zd);

	zdev->nr_empty_zones = 0;

	if (zbc_mt_zd(zdev))
		return zbc_format_meta_zd(zdev, cfg);
	if (zbc_mt_zoned(zdev))
		return zbc_format_meta_zoned(zdev, cfg);
	return zbc_format_meta_nz(zdev, cfg);
}

static void __zbc_close_zone(struct zbc_dev *zdev, struct zbc_zone *zone);

/*
 * Initialize metadata.
 */
static int zbc_init_meta(struct zbc_dev *zdev)
{
	struct zbc_zone *zone;
	unsigned int i;
	int ret;

	/* Mmap metadata */
	ret = zbc_map_meta(zdev, false);
	if (ret)
		return ret;

	/* Close all zones */
	zone = zdev->zones;
	for (i = 0; i < zdev->nr_zones; i++) {
		__zbc_close_zone(zdev, zone);
		zone++;
	}
	zdev->nr_imp_open = 0;
	zdev->nr_exp_open = 0;

	return 0;
}

static bool zbc_print_config(struct tcmu_device *dev, struct zbc_dev *zdev,
			     bool print_full)
{
	struct zbc_dev_config *cfg = &zdev->cfg;

	tcmu_dev_dbg(dev, "Device type: %u, model %u : %s\n", zdev->dev_type,
		     zdev->dev_model.zd, zdev->dev_feat->opt_name);

	switch (zdev->dev_type) {
	case ZBC_MT_ZONE_DOM:
		tcmu_dev_dbg(dev, "%s: Zone Domains DH-SMR device\n",
			     cfg->path);
		zbc_print_config_zd(zdev);
		if (print_full)
			zbc_print_realms(zdev);
		break;
	case ZBC_MT_NON_ZONED:
		tcmu_dev_dbg(dev, "%s: Non-zoned PMR device\n", cfg->path);
		zbc_print_config_nz(zdev);
		break;
	case ZBC_MT_HM_ZONED:
		tcmu_dev_dbg(dev, "%s: HM zoned SMR device\n", cfg->path);
		zbc_print_config_zoned(zdev);
		break;
	case ZBC_MT_HA_ZONED:
		tcmu_dev_dbg(dev, "%s: HA zoned SMR device\n", cfg->path);
		zbc_print_config_zoned(zdev);
		break;
	default:
		tcmu_dev_err(dev, "Invalid device type %u\n", zdev->dev_type);
		return false;
	}

	return true;
}

/*
 * Open the emulated backstore file.
 * If the file does not exist, it is created and metadata formatted.
 */
static int zbc_open_backstore(struct tcmu_device *dev)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	struct zbc_dev_config *cfg = &zdev->cfg;
	struct stat st;
	int i, ret;
	bool new = false;

	/* Get stats */
	ret = stat(cfg->path, &st);
	if (ret && errno == ENOENT) {
		cfg->need_format = true;
		new = true;
		tcmu_dev_dbg(dev, "New backstore file %s\n", cfg->path);
	} else {
		tcmu_dev_dbg(dev, "Using backstore file %s\n", cfg->path);
		if (!S_ISREG(st.st_mode)) {
			tcmu_dev_err(dev, "%s is not a regular file\n",
				     cfg->path);
			return -EINVAL;
		}
	}

	/* Open the file */
	zdev->fd = open(cfg->path, O_CREAT | O_RDWR | O_LARGEFILE, 0600);
	if (zdev->fd == -1) {
		ret = -errno;
		tcmu_dev_err(dev, "Open %s failed (%m)\n", cfg->path);
		return ret;
	}

	if (new) {
		ret = stat(cfg->path, &st);
		if (ret) {
			tcmu_dev_err(dev, "Can't stat backstore file %s\n",
				cfg->path);
			return -EINVAL;
		}
	}

	if (!zbc_dev_check_meta(dev, &st))
		cfg->need_format = true;

	if (cfg->need_format) {
		if (zbc_get_dev_features(zdev->dev_type, zdev->dev_model)) {
			if (!new) {
				/* Metadata got messed up */
				tcmu_dev_err(dev,
					"BACKSTORE %s NEEDS REFORMATTING!\n",
					cfg->path);
			}
			cfg->mutating = true;
			ret = zbc_format_meta(zdev);
			cfg->mutating = false;
		} else {
			zdev->dev_type = cfg->dev_type;
			ret = zbc_format_meta(zdev);
		}
	} else {
		ret = zbc_init_meta(zdev);
	}
	if (ret)
		goto err;

	zdev->meta->time_checked = time(NULL);

	/* Count the number of empty zones to init zdev->nr_empty_zones */
	zdev->nr_empty_zones = 0;
	for (i = 0; i < zdev->nr_zones; i++) {
		if (zbc_zone_empty(&zdev->zones[i]))
			zdev->nr_empty_zones++;
		if (zbc_zone_gap(&zdev->zones[i]))
			zdev->have_gaps = true;
	}
	zdev->min_empty_zones = zdev->nr_empty_zones;

	tcmu_set_dev_block_size(dev, zdev->lba_size);
	tcmu_set_dev_num_lbas(dev, zdev->logical_capacity);

	if (!zbc_print_config(dev, zdev, true)) {
		/* bad zdev->dev_type */
		ret = -1;
		goto err;
	}

	return 0;

err:
	close(zdev->fd);

	return ret;
}

/*
 * Ready the emulated device.
 */
static int zbc_open(struct tcmu_device *dev, bool reopen)
{
	struct zbc_dev *zdev;
	struct zbc_dev_config *cfg;
	char *err = NULL;
	int ret;

	tcmu_dev_dbg(dev, "Configuration string: %s\n",
		     tcmu_get_dev_cfgstring(dev));

	zdev = calloc(1, sizeof(*zdev));
	if (!zdev)
		return -ENOMEM;

	tcmu_set_dev_private(dev, zdev);
	zdev->dev = dev;

	/* Parse config */
	cfg = &zdev->cfg;
	if (!zbc_parse_config(tcmu_get_dev_cfgstring(dev), cfg, &err)) {
		if (err) {
			tcmu_dev_err(dev, "%s\n", err);
			free(err);
		}
		ret = -EINVAL;
		goto err;
	}

	/* Get backstore capacity requested */
	cfg->phys_capacity = tcmu_get_dev_size(dev);
	if (cfg->phys_capacity == -1) {
		tcmu_dev_err(dev, "Could not get device size\n");
		ret = -ENODEV;
		goto err;
	}

	/* Open the backstore file */
	ret = zbc_open_backstore(dev);
	if (ret)
		goto err;

	return 0;

err:
	if (cfg->path)
		free(cfg->path);
	free(zdev);
	return ret;
}

/*
 * Cleanup resources used by the emulated device.
 */
static void zbc_close(struct tcmu_device *dev)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);

	zbc_unmap_meta(zdev);

	tcmu_dev_dbg(dev, "%s %s %llu commands processed\n",
			__func__, zdev->cfg.path, zdev->nr_cdb_cmds);

	if (zdev->cmr_nr_zones_to_smr)
		free(zdev->cmr_nr_zones_to_smr);
	if (zdev->smr_nr_zones_to_cmr)
		free(zdev->smr_nr_zones_to_cmr);
	close(zdev->fd);
	free(zdev->cfg.path);
	free(zdev);
}

static void fill_naa_id(char *ptr, char *wwn)
{
	char *p;
	int i;
	unsigned char val;
	bool next = true;

	ptr[0] = 1; /* code set: binary */
	ptr[1] = 3; /* identifier: NAA */
	ptr[3] = 16; /* body length for naa registered extended format */

	/*
	 * Set type 6 and use OpenFabrics IEEE Company ID: 00 14 05
	 */
	ptr[4] = 0x60;
	ptr[5] = 0x01;
	ptr[6] = 0x40;
	ptr[7] = 0x50;

	/*
	 * Fill in the rest with a binary representation of WWN
	 *
	 * This implementation only uses a nibble out of every byte of
	 * WWN, but this is what the kernel does, and it's nice for our
	 * values to match.
	 */
	p = wwn;
	for (i = 7; *p && i < 20; p++) {

		if (!char_to_hex(&val, *p))
			continue;

		if (next) {
			next = false;
			ptr[i++] |= val;
		} else {
			next = true;
			ptr[i] = val << 4;
		}
	}
}

/*
 * VPD page inquiry.
 */
static int zbc_evpd_inquiry(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	const struct zbc_dev_features *feat = zdev->dev_feat;
	uint8_t *cdb = cmd->cdb;
	struct iovec *iovec = cmd->iovec;
	size_t iov_cnt = cmd->iov_cnt;
	size_t len, used = 0;
	uint8_t data[512];
	char *ptr, *wwn, *p;
	unsigned int i, max_xfer_len, max_activate;

	/*
	 * Zero the output buffer. This also sets the returned
	 * device type to be 0x00: a regular SCSI device.
	 */
	memset(data, 0, sizeof(data));
	data[0] = zbc_mt_hm(zdev) ? ZBC_HM : 0x00; /* Block device type */
	data[1] = cdb[2];

	switch (cdb[2]) {

	case 0x00:
		/* Supported VPD pages */
		i = 4;
		data[i++] = 0x80;
		data[i++] = 0x83;
		data[i++] = 0xb0;
		data[i++] = 0xb1;
		if (zbc_mt_zoned(zdev))
			data[i++] = 0xb6;
		data[3] = i - 4;

		tcmu_memcpy_into_iovec(iovec, iov_cnt, data, i);
		break;

	case 0x80:
		/* Unit Serial Number - emit unscrambled WWN */
		wwn = tcmu_get_wwn(dev);
		if (!wwn)
			return zbc_set_sense(cmd, HARDWARE_ERROR,
					     ASC_INTERNAL_TARGET_FAILURE);

		ptr = (char *)&data[4];

		p = wwn;
		for (i = 0; *p && i < 36; i++) {
			*ptr++ = *p++;
			used++;
		}

		zbc_cpbe16(&data[2], used);

		tcmu_memcpy_into_iovec(iovec, iov_cnt, data, used + 4);

		free(wwn);
		break;

	case 0x83:
		/* Device identification */
		wwn = tcmu_get_wwn(dev);
		if (!wwn)
			return zbc_set_sense(cmd, HARDWARE_ERROR,
					     ASC_INTERNAL_TARGET_FAILURE);

		ptr = (char *)&data[4];

		/* 1/5: T10 Vendor id */
		ptr[0] = 2; /* code set: ASCII */
		ptr[1] = 1; /* identifier: T10 vendor id */
		memcpy(&ptr[4], "LIO-ORG ", 8);
		len = snprintf(&ptr[12], sizeof(data) - 16, "%s", wwn);

		ptr[3] = 8 + len + 1;
		used += (uint8_t)ptr[3] + 4;
		ptr += used;

		/* 2/5: NAA binary */
		fill_naa_id(ptr, wwn);

		used += 20;

		zbc_cpbe16(&data[2], used);

		tcmu_memcpy_into_iovec(iovec, iov_cnt, data, used + 4);

		free(wwn);
		break;

	case 0xb0:
		/* Block Limits */

		/* Page length (003Ch)*/
		zbc_cpbe16(&data[2], 0x3c);

		/*
		 * WSNZ = 1: the device server won't support a value of zero
		 * in the NUMBER OF LOGICAL BLOCKS field in the WRITE SAME
		 * command CDBs
		 */
		data[4] = 0x01;

		/*
		 * From SCSI Commands Reference Manual, section Block Limits
		 * VPD page (B0h)
		 *
		 * MAXIMUM COMPARE AND WRITE LENGTH: set to a non-zero value
		 * indicates the maximum value that the device server accepts
		 * in the NUMBER OF LOGICAL BLOCKS field in the COMPARE AND
		 * WRITE command.
		 *
		 * It should be less than or equal to MAXIMUM TRANSFER LENGTH.
		 */
		data[5] = 0x01;

		/* Max xfer length */
		max_xfer_len = tcmu_get_dev_max_xfer_len(dev);
		if (!max_xfer_len)
			return zbc_set_sense(cmd, HARDWARE_ERROR,
					     ASC_INTERNAL_TARGET_FAILURE);
		zbc_cpbe32(&data[8], max_xfer_len);

		/* Optimal xfer length */
		zbc_cpbe32(&data[12], max_xfer_len);

		/* MAXIMUM WRITE SAME LENGTH */
		zbc_cpbe64(&data[36], VPD_MAX_WRITE_SAME_LENGTH);

		tcmu_memcpy_into_iovec(iovec, iov_cnt, data, 64);

		break;

	case 0xb1:
		/* Block Device Characteristics VPD page */

		/* Page length (003Ch)*/
		zbc_cpbe16(&data[2], 0x3c);

		/* 7200 RPM */
		zbc_cpbe16(&data[4], 0x1c20);

		data[8] = 0x02; /* Set FUAB because we have flush */
		if (zbc_mt_ha(zdev))
			data[8] |= 0x10; /* Set ZONED for HA. 00h for HM/ZD */
		if (zbc_mt_zd(zdev))
			/* Zone Domains command set is supported */
			data[8] |= 0x40;

		/* FIXME the bit below is ad-hoc, testing only */
		data[9] = 0x01; /* MUTATE support */

		tcmu_memcpy_into_iovec(iovec, iov_cnt, data, 64);
		break;

	case 0xb6:
		/* Zoned Block Device Characteristics VPD page */

		if (!zbc_mt_zoned(zdev))
			return zbc_set_sense(cmd, ILLEGAL_REQUEST,
					     ASC_INVALID_FIELD_IN_CDB);

		/* Page length (003Ch)*/
		zbc_cpbe16(&data[2], 0x3c);

		/* Unrestricted reads (URSWRZ) */
		data[4] = zdev->wp_check ? 0x00 : 0x01;

		if (zbc_mt_zd(zdev)) {
			/* Zone Domains Capabilities */

			/* MAXIMUM ACTIVATION control (vendor-specific) */
			if (feat->max_act_control)
				data[4] |= 0x04;

			/* NOZSRC support */
			if (!feat->no_nozsrc)
				data[4] |= 0x08;

			/* URSWRZ control */
			if (!feat->no_ur_control)
				data[4] |= 0x10;

			/* REPORT REALMS support */
			if (zdev->realms_feat_set && !feat->no_report_realms)
				data[4] |= 0x20;

			/* Zone Domains control */
			if (!feat->no_za_control)
				data[4] |= 0x80;

			/* Zone Types Supported */
			if (feat->actv_of_conv)
				data[10] |= 0x01;
			if (feat->actv_of_seq_pref)
				data[10] |= 0x02;
			if (feat->actv_of_seq_req)
				data[10] |= 0x04;
			if (feat->actv_of_sobr)
				data[10] |= 0x08;
			if (zdev->have_gaps)
				data[10] |= 0x10;

			/* Maximum subsequent number of zones */
			max_activate = zdev->max_activate;
			if (max_activate > zdev->nr_zones)
				max_activate = 0;
			zbc_cpbe16(&data[20], max_activate);
		}

		if (zbc_mt_ha(zdev)) {
			/*
			 * Optimal number of open sequential write
			 * preferred zones.
			 */
			zbc_cpbe32(&data[8], zdev->nr_open_zones);

			/*
			 * Optimal number of non-sequentially written
			 * sequential write preferred zones.
			 */
			zbc_cpbe32(&data[12], zdev->nr_open_zones);
		} else {
			/*
			 * Maximum number of open sequential write
			 * required zones.
			 */
			zbc_cpbe32(&data[16], zdev->nr_open_zones);
		}

		tcmu_memcpy_into_iovec(iovec, iov_cnt, data, 64);
		break;

	default:
		tcmu_dev_dbg(dev, "Unsupported Vital Product Data page 0x%X\n",
			     cdb[2]);
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_INVALID_FIELD_IN_CDB);
	}

	return TCMU_STS_OK;
}

/*
 * Standard inquiry.
 */
static int zbc_std_inquiry(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	uint8_t buf[36];

	memset(buf, 0, sizeof(buf));
	buf[0] = zbc_mt_hm(zdev) ? ZBC_HM : 0x00; /* Block device type */
	buf[2] = 0x05; /* SPC-3 */
	buf[3] = 0x02; /* response data format */
	buf[4] = 31; /* Set additional length to 31 */
	buf[7] = 0x02; /* CmdQue */
	memcpy(&buf[8], "LIO-ORG ", 8);
	memcpy(&buf[16], "TCMU DH-SMR dev", 15);
	memcpy(&buf[32], "0002", 4);

	tcmu_memcpy_into_iovec(cmd->iovec, cmd->iov_cnt, buf, sizeof(buf));

	return TCMU_STS_OK;
}

/*
 * Inquiry command emulation.
 */
static int zbc_inquiry(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	uint8_t *cdb = cmd->cdb;

	if (cdb[1] & 0x01) {
		/* VPD inquiry */
		return zbc_evpd_inquiry(dev, cmd);
	}

	if (cdb[2]) {
		/* No page code for standard inquiry */
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_INVALID_FIELD_IN_CDB);
	}

	/* Standard inquiry */
	return zbc_std_inquiry(dev, cmd);
}

/*
 * Test if a zone must be reported.
 */
static bool zbc_should_report_zone(struct zbc_zone *zone,
				   enum zbc_rz_rpt_options ro)
{
	enum zbc_rz_rpt_options options = ro & ((uint8_t)~ZBC_RZ_RO_PARTIAL);

	switch (options) {
	case ZBC_RZ_RO_ALL:
		return true;
	case ZBC_RZ_RO_EMPTY:
		return zbc_zone_empty(zone);
	case ZBC_RZ_RO_IMP_OPEN:
		return zbc_zone_imp_open(zone);
	case ZBC_RZ_RO_EXP_OPEN:
		return zbc_zone_exp_open(zone);
	case ZBC_RZ_RO_CLOSED:
		return zbc_zone_closed(zone);
	case ZBC_RZ_RO_FULL:
		return zbc_zone_full(zone);
	case ZBC_RZ_RO_READONLY:
		return zbc_zone_rdonly(zone);
	case ZBC_RZ_RO_OFFLINE:
		return zbc_zone_offline(zone);
	case ZBC_RZ_RO_INACTIVE:
		return zbc_zone_inactive(zone);
	case ZBC_RZ_RO_RWP_RECMND:
		return zbc_zone_rwp(zone);
	case ZBC_RZ_RO_NON_SEQ:
		return zbc_zone_non_seq(zone);
	case ZBC_RZ_RO_GAP:
		return zbc_zone_gap(zone);
	case ZBC_RZ_RO_NOT_WP:
		return zbc_zone_not_wp(zone);
	default:
		return false;
	}
}

/*
 * Report zones command emulation.
 */
static int zbc_report_zones(struct tcmu_device *dev,
			    struct tcmulib_cmd *cmd, bool partial,
			    uint8_t ro, uint64_t start_lba,
			    size_t len)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	struct zbc_zone *zone;
	struct iovec *iovec = cmd->iovec;
	size_t iov_cnt = cmd->iov_cnt;
	unsigned int nr_zones = 0;
	uint8_t data[ZBC_ZONE_DESCRIPTOR_LENGTH];
	uint64_t lba;

	lba = start_lba;
	if (lba >= zdev->logical_capacity)
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_LBA_OUT_OF_RANGE);

	/* Check reporting option */
	switch (ro) {
	case ZBC_RZ_RO_ALL:
	case ZBC_RZ_RO_EMPTY:
	case ZBC_RZ_RO_IMP_OPEN:
	case ZBC_RZ_RO_EXP_OPEN:
	case ZBC_RZ_RO_CLOSED:
	case ZBC_RZ_RO_FULL:
	case ZBC_RZ_RO_INACTIVE:
	case ZBC_RZ_RO_READONLY:
	case ZBC_RZ_RO_OFFLINE:
	case ZBC_RZ_RO_RWP_RECMND:
	case ZBC_RZ_RO_NON_SEQ:
	case ZBC_RZ_RO_NOT_WP:
		break;
	default:
		tcmu_dev_warn(dev,
			      "Unknown REPORT ZONES reporting option 0x%x\n",
			      ro);
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_INVALID_FIELD_IN_CDB);
	}

	/* First pass: count zones */
	if (len > ZBC_ZONE_DESCRIPTOR_OFFSET)
		len -= ZBC_ZONE_DESCRIPTOR_OFFSET;
	else
		len = 0;
	zone = zbc_get_zone(zdev, lba, false);
	if (!zone) {
		tcmu_dev_warn(dev, "Bad zone LBA %"PRIu64"\n", lba);
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_INVALID_FIELD_IN_CDB);
	}
	while (lba < zdev->logical_capacity) {

		if (zbc_should_report_zone(zone, ro)) {
			if (partial && len < ZBC_ZONE_DESCRIPTOR_LENGTH)
				break;
			if (len > ZBC_ZONE_DESCRIPTOR_LENGTH)
				len -= ZBC_ZONE_DESCRIPTOR_LENGTH;
			else
				len = 0;
			nr_zones++;
		}

		lba = zone->start + zone->len;
		zone++;

	}

	/* Setup report header */
	memset(data, 0, sizeof(data));
	zbc_cpbe32(&data[0], nr_zones * ZBC_ZONE_DESCRIPTOR_LENGTH);
	zbc_cpbe64(&data[8], zdev->logical_capacity - 1);

	len = tcmu_memcpy_into_iovec(iovec, iov_cnt, data,
				     ZBC_ZONE_DESCRIPTOR_OFFSET);
	if (len < ZBC_ZONE_DESCRIPTOR_OFFSET)
		return TCMU_STS_OK;

	/* Second pass: get zone information */
	len = tcmu_iovec_length(iovec, iov_cnt);
	lba = start_lba;
	zone = zbc_get_zone(zdev, lba, false);
	while (lba < zdev->logical_capacity &&
	       len >= ZBC_ZONE_DESCRIPTOR_LENGTH) {
		if (zbc_should_report_zone(zone, ro)) {
			memset(data, 0, sizeof(data));
			data[0] = zone->type & 0x0f;
			data[1] = (zone->cond << 4) & 0xf0;
			if (zone->reset)
				data[1] |= 0x01;
			if (zone->non_seq)
				data[1] |= 0x02;
			zbc_cpbe64(&data[8], zone->len);
			zbc_cpbe64(&data[16], zone->start);
			zbc_cpbe64(&data[24], zone->wp);

			tcmu_memcpy_into_iovec(iovec, iov_cnt, data,
					       ZBC_ZONE_DESCRIPTOR_LENGTH);
			len -= ZBC_ZONE_DESCRIPTOR_LENGTH;
		}

		lba = zone->start + zone->len;
		zone++;
	}

	return TCMU_STS_OK;
}

/*
 * SCSI-specific REPORT ZONES handler.
 */
static int zbc_scsi_report_zones(struct tcmu_device *dev,
				 struct tcmulib_cmd *cmd)
{
	uint8_t *cdb = cmd->cdb;
	uint64_t lba = tcmu_get_lba(cdb);
	size_t len = tcmu_get_xfer_length(cdb);
	bool partial = cdb[14] & ZBC_RZ_RO_PARTIAL;
	uint8_t ro = cdb[14] & (~ZBC_RZ_RO_PARTIAL);

	return zbc_report_zones(dev, cmd, partial, ro, lba, len);
}

/*
 * Check the given LBA range against the device capacity.
 */
static inline int zbc_lba_out_of_range(struct zbc_dev *zdev,
				       struct tcmulib_cmd *cmd,
				       uint64_t lba, size_t nr_lbas)
{
	return (lba >= zdev->logical_capacity ||
		lba + nr_lbas > zdev->logical_capacity ||
		lba + nr_lbas < lba);
}

/*
 * Count the number of active zones in a zone domain
 */
static unsigned int zbc_count_active_domain_zones(struct zbc_dev *zdev,
						  struct zbc_zone_domain *d)
{
	struct zbc_zone *zone;
	unsigned int i, active_zn = 0;

	zone = zbc_get_zone(zdev, d->start_lba, false);
	if (!zone)
		return 0;
	for (i = 0; i < d->nr_zones; i++, zone++) {
		if (!zbc_zone_inactive(zone) && !zbc_zone_offline(zone))
			active_zn++;
	}

	return active_zn;
}

static bool zbc_should_report_domain(struct zbc_dev *zdev,
				     struct zbc_zone_domain *d,
				     enum zbc_rzd_rpt_options ro)
{
	unsigned int active_zn;

	if (ro == ZBC_RZD_RO_ALL)
		return true;

	active_zn = zbc_count_active_domain_zones(zdev, d);
	switch (ro) {
	case ZBC_RZD_RO_ALL_ACTIVE:
		if (active_zn == d->nr_zones)
			return true;
		break;

	case ZBC_RZD_RO_ACTIVE:
		if (active_zn)
			return true;
		break;

	case ZBC_RZD_RO_INACTIVE:
		if (!active_zn)
			return true;
		break;

	default:
		tcmu_dev_warn(zdev->dev,
			"Bad REPORT ZONE DOMAINS reporting option 0x%x\n", ro);
	}

	return false;
}

/*
 * REPORT ZONE DOMAINS command emulation.
 */
static int zbc_report_zone_domains(struct tcmu_device *dev,
				   struct tcmulib_cmd *cmd,
				   enum zbc_rzd_rpt_options ro,
				   uint64_t start_lba, size_t len)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	struct zbc_zone_domain *d = zdev->domains;
	struct zbc_zone *zone;
	struct iovec *iovec = cmd->iovec;
	size_t iov_cnt = cmd->iov_cnt;
	unsigned int start_dom;
	unsigned int i, nr_domains = zdev->nr_domains, nr_rpt_domains = 0;
	uint8_t data[ZBC_RPT_DOMAINS_RECORD_SIZE];

	/* Validate reporting options */
	switch (ro) {
	case ZBC_RZD_RO_ALL:
	case ZBC_RZD_RO_ALL_ACTIVE:
	case ZBC_RZD_RO_ACTIVE:
	case ZBC_RZD_RO_INACTIVE:
		break;
	default:
		tcmu_dev_warn(dev,
			"Unknown REPORT ZONE DOMAINS reporting option 0x%x\n",
			ro);
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_INVALID_FIELD_IN_CDB);
	}

	/* Validate the domain locator */
	if (zbc_lba_out_of_range(zdev, cmd, start_lba, 0)) {
		tcmu_dev_warn(dev, "Domain locator LBA %"PRIu64
				   " is out of range\n",
			      start_lba);
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_LBA_OUT_OF_RANGE);
	}
	zone = zbc_get_zone(zdev, start_lba, false);
	if (!zone)
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_INVALID_FIELD_IN_CDB);
	if (zbc_zone_gap(zone)) {
		tcmu_dev_warn(dev, "Domain locator LBA %"PRIu64
				   " points to a gap zone\n",
			      start_lba);
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_ATTEMPT_TO_ACCESS_GAP_ZONE);
	}

	/* Skip all the domains that end below the locator LBA */
	for (start_dom = 0; start_dom < nr_domains; start_dom++, d++) {
		if (d->end_lba >= start_lba)
			break;
	}
	if (start_dom >= nr_domains) {
		tcmu_dev_err(dev, "Can't locate domain %lu\n",
			     start_lba);
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_INVALID_FIELD_IN_CDB);
	}

	/* Find out the number of domains to report */
	for (i = start_dom; i < nr_domains; i++, d++) {
		if (zbc_should_report_domain(zdev, d, ro))
			nr_rpt_domains++;
	}

	/* Set up the report header */
	memset(data, 0, ZBC_RPT_DOMAINS_HEADER_SIZE);
	len = ZBC_RPT_DOMAINS_HEADER_SIZE +
	      nr_domains * ZBC_RPT_DOMAINS_RECORD_SIZE;
	zbc_cpbe32(data, len); /* LENGTH AVAILABLE */
	len = ZBC_RPT_DOMAINS_HEADER_SIZE +
	      nr_rpt_domains * ZBC_RPT_DOMAINS_RECORD_SIZE;
	zbc_cpbe32(&data[4], len); /* LENGTH RETURNED */
	data[8] = nr_domains;
	data[9] = nr_rpt_domains;
	data[10] = ro;
	zbc_cpbe64(&data[16], start_lba);

	len = tcmu_memcpy_into_iovec(iovec, iov_cnt, data,
				     ZBC_RPT_DOMAINS_HEADER_SIZE);
	if (len < ZBC_RPT_DOMAINS_HEADER_SIZE)
		goto out;

	len = tcmu_iovec_length(iovec, iov_cnt);
	d = &zdev->domains[start_dom];
	for (i = start_dom; i < nr_domains; i++, d++) {
		if (len < ZBC_RPT_DOMAINS_RECORD_SIZE)
			break;
		if (!zbc_should_report_domain(zdev, d, ro))
			continue;

		memset(data, 0, ZBC_RPT_DOMAINS_RECORD_SIZE);
		data[0] = i; /* ZONE DOMAIN ID */
		zbc_cpbe64(&data[16], d->nr_zones); /* ZONE COUNT */
		zbc_cpbe64(&data[24], d->start_lba); /* START LBA */
		zbc_cpbe64(&data[32], d->end_lba); /*END LBA */
		data[40] = d->type; /* ZONE TYPE */
		data[41] = 0x02; /* VALID DOMAIN ZONE TYPE */

		len -= tcmu_memcpy_into_iovec(iovec, iov_cnt, data,
					      ZBC_RPT_DOMAINS_RECORD_SIZE);
	}

out:
	return TCMU_STS_OK;
}

/*
 * SCSI-specific REPORT ZONE DOMAINS handler.
 */
static int zbc_scsi_report_zone_domains(struct tcmu_device *dev,
					struct tcmulib_cmd *cmd)
{
	uint8_t *cdb = cmd->cdb;
	uint64_t lba = tcmu_get_lba(cdb);
	size_t len = tcmu_get_xfer_length(cdb);
	uint8_t ro = cdb[14] & 0x3f; /* FIXME field format TBD for SCSI */

	return zbc_report_zone_domains(dev, cmd, ro, lba, len);
}

/*
 * Test if a realm must be reported.
 */
static bool zbc_should_report_realm(struct tcmu_device *dev,
				    struct zbc_zone_realm *r,
				    enum zbc_rr_rpt_options ro)
{
	switch (ro) {
	case ZBC_RR_RO_ALL:
		return true;

	case ZBC_RR_RO_SOBR:
		if (zbc_realm_sobr(r))
			return true;
		break;

	case ZBC_RR_RO_SWR:
		if (zbc_realm_seq_r(r))
			return true;
		break;

	case ZBC_RR_RO_SWP:
		if (zbc_realm_seq_p(r))
			return true;
		break;

	default:
		tcmu_dev_err(dev,
			     "Bad realm reporting option 0x%x\n", ro);
	}

	return false;
}

/*
 * REPORT REALMS command emulation.
 */
static int zbc_report_realms(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			     enum zbc_rr_rpt_options ro, uint64_t start_lba,
			     size_t len)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	struct zbc_zone *zone;
	struct zbc_zone_domain *d;
	struct zbc_zone_realm *r;
	struct zbc_realm_item *ri;
	uint8_t *ptr;
	struct iovec *iovec = cmd->iovec;
	size_t iov_cnt = cmd->iov_cnt;
#ifdef ZBC_NEW_RPT_REALMS
	uint64_t rhi, next = 0LL;
#else
	uint64_t rhi;
#endif
	int j;
	unsigned int i, nr_realms = zdev->nr_realms;
	unsigned int nr_rpt_realms = 0, desc_len;
#ifdef ZBC_NEW_RPT_REALMS
	unsigned int zt, sz;
#endif
	uint8_t data[ZBC_RPT_REALMS_RECORD_SIZE];

#ifdef ZBC_NEW_RPT_REALMS
	/* Validate reporting options */
	switch (ro) {
	case ZBC_RR_RO_ALL:
	case ZBC_RR_RO_SOBR:
	case ZBC_RR_RO_SWR:
	case ZBC_RR_RO_SWP:
		break;
	default:
		tcmu_dev_warn(dev,
			      "Unknown realm reporting option 0x%x\n",
			      ro);
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_INVALID_FIELD_IN_CDB);
	}
#else
	ro = ZBC_RR_RO_ALL; /* Force all realms to be reported */
#endif

	/* Validate the realm locator */
	if (zbc_lba_out_of_range(zdev, cmd, start_lba, 0)) {
		tcmu_dev_warn(dev, "Realm locator LBA %"PRIu64
				   " is out of range\n",
			      start_lba);
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_LBA_OUT_OF_RANGE);
	}
	zone = zbc_get_zone(zdev, start_lba, false);
	if (!zone)
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_INVALID_FIELD_IN_CDB);
	if (zbc_zone_gap(zone)) {
		tcmu_dev_warn(dev, "Realm locator LBA %"PRIu64
				   " points to a gap zone\n",
			      start_lba);
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_ATTEMPT_TO_ACCESS_GAP_ZONE);
	}

#ifdef ZBC_NEW_RPT_REALMS
	/* Get the starting realm to report */
	j = zbc_get_zone_realm(zdev, start_lba, false, &zt);
	if (j < 0) {
		tcmu_dev_warn(dev, "Invalid realm locator %"PRIu64"\n",
			      start_lba);
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_INVALID_FIELD_IN_CDB);
	}

	if (len < ZBC_RPT_REALMS_HEADER_SIZE) {
		tcmu_dev_warn(dev,
			      "REPORT REALMS allocated length %lu too tiny\n",
			      len);
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_INVALID_FIELD_IN_CDB);
	}

	/* Calculate realm descriptor length */
	desc_len = ZBC_RR_START_END_DESC_SIZE * zdev->nr_domains +
		   ZBC_RPT_REALMS_DESC_OFFSET;

	/*
	 * Find out the number of realms to report. Also, check
	 * if we will be able to output all the required realms.
	 * If not, save the start LBA of the first non-reported realm.
	 */
	sz = len - ZBC_RPT_REALMS_HEADER_SIZE;
	for (i = j, r = &zdev->realms[j]; i < nr_realms; i++, r++) {
		if (zbc_should_report_realm(dev, r, ro)) {
			if (sz < desc_len) {
				next = zbc_realm_start(r, zt);
				break;
			}
			nr_rpt_realms++;
			sz -= desc_len;
		}
	}

	if (next && next == start_lba) {
		/*
		 * The client should have allocated a large enough buffer
		 * to hold at least one realm descriptor, but no...
		 */
		tcmu_dev_warn(dev,
			      "REPORT REALMS allocated length %lu too small\n",
			      len);
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_INVALID_FIELD_IN_CDB);
	}

#else
	desc_len = ZBC_RPT_REALMS_RECORD_SIZE;
	j = 0; /* Always from the beginning */
#endif

	/* Set up report header */
	memset(data, 0, ZBC_RPT_REALMS_HEADER_SIZE);
	zbc_cpbe32(&data[0], nr_realms);
#ifdef ZBC_NEW_RPT_REALMS
	zbc_cpbe32(&data[4], desc_len);
	zbc_cpbe64(&data[8], next);
#endif

	len = tcmu_memcpy_into_iovec(iovec, iov_cnt, data,
				     ZBC_RPT_REALMS_HEADER_SIZE);
	if (len < ZBC_RPT_REALMS_HEADER_SIZE)
		goto out;

	len = tcmu_iovec_length(iovec, iov_cnt);
	for (r = &zdev->realms[j]; j < nr_realms; j++, r++)  {
		if (len < desc_len)
			break;
		if (!zbc_should_report_realm(dev, r, ro))
			continue;

		memset(data, 0, desc_len);
#ifdef ZBC_NEW_RPT_REALMS
		zbc_cpbe32(data, r->number);
		zbc_cpbe16(&data[4], r->restr);
		data[7] = zbc_domain_id(zdev, r->type);
		d = zdev->domains;
		ptr = data + ZBC_RPT_REALMS_DESC_OFFSET;
		for (i = 0; i < zdev->nr_domains; i++, d++) {
			if (zbc_can_actv_realm_as(r, d->type)) {
				ri = zbc_get_realm_item(r, d->type);
				zbc_cpbe64(ptr, ri->start_lba);
				rhi = ri->start_lba +
				      ri->length * zdev->zone_size - 1;
				zbc_cpbe64(ptr + 8, rhi);
			}
			ptr += ZBC_RR_START_END_DESC_SIZE;
		}
#else
		data[0] = zbc_domain_id(zdev, r->type);
		zbc_cpbe16(&data[2], r->number);
		d = zdev->domains;
		ptr = data + ZBC_RPT_REALMS_DESC_OFFSET;
		for (i = 0; i < zdev->nr_domains; i++, d++) {
			if (zbc_can_actv_realm_as(r, d->type)) {
				data[1] |= 1 << i; /* Activation flags */
				ri = zbc_get_realm_item(r, d->type);
				zbc_cpbe64(ptr, ri->start_lba);
				rhi = ri->start_lba +
				      ri->length * zdev->zone_size - 1;
				zbc_cpbe64(ptr + 8, rhi);
			}
			ptr += ZBC_RPT_REALMS_ITEM_SIZE;
		}
#endif

		len -= tcmu_memcpy_into_iovec(iovec, iov_cnt, data, desc_len);
		if (!--nr_rpt_realms)
			break;
	}
out:
	return TCMU_STS_OK;
}

/*
 * SCSI-specific REPORT REALMS handler.
 */
static int zbc_scsi_report_realms(struct tcmu_device *dev,
				  struct tcmulib_cmd *cmd)
{
	uint8_t *cdb = cmd->cdb;
	uint64_t lba = tcmu_get_lba(cdb);
	size_t len = tcmu_get_xfer_length(cdb);
	uint8_t ro = cdb[14] & 0x3f; /* FIXME field format TBD for SCSI */

	return zbc_report_realms(dev, cmd, ro, lba, len);
}

/*
 * Called when the condition of a zone is about to change. Check if the zone is
 * empty and the new condition is not. if this is the case, modify the stats
 * accordingly.
 */
static inline void zbc_on_cond_change(struct zbc_dev *zdev,
				      struct zbc_zone *zone,
				      enum zbc_zone_cond cond)
{
	if (zbc_zone_empty(zone) && cond != ZBC_ZONE_COND_EMPTY) {
		zdev->nr_empty_zones--;
		if (zdev->min_empty_zones > zdev->nr_empty_zones)
			zdev->min_empty_zones = zdev->nr_empty_zones;
	}
}

/*
 * Check if we can open another add_val SWR zones without exceeding the maximum.
 */
static inline bool zbc_ozr_check(struct zbc_dev *zdev, unsigned int add_val)
{
	if (zdev->nr_exp_open + add_val > zdev->nr_open_zones) {
		tcmu_dev_warn(zdev->dev,
			"Insufficient zone resources: eopen=%u + add=%u > max=%u\n",
			zdev->nr_exp_open, add_val, zdev->nr_open_zones);
		return false;
	}

	return true;
}

/*
 * Given the LBA, get the zone for a zone operation and
 * perform a few checks that are common for all the ops.
 */
static int zbc_get_check_zone(struct zbc_dev *zdev, struct tcmulib_cmd *cmd,
			      uint64_t lba, unsigned int count,
			      struct zbc_zone **pzone, struct zbc_zone **plast,
			      const char **err)
{
	struct zbc_zone *zone, *z, *last;

	if (zbc_lba_out_of_range(zdev, cmd, lba, zdev->zone_size)) {
		*err = "ZONE ID out of range";
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_LBA_OUT_OF_RANGE);
	}

	zone = zbc_get_zone(zdev, lba, true);
	if (!zone) {
		*err = "cannot get zone";
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_INVALID_FIELD_IN_CDB);
	}
	if (zbc_zone_gap(zone)) {
		*err = "zone is GAP";
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_ATTEMPT_TO_ACCESS_GAP_ZONE);
	}
	if (zbc_zone_conv(zone)) {
		*err = "zone is Conventional";
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_INVALID_FIELD_IN_CDB);
	}

	last = zone + count - 1;
	if (count <= 1) {
		if (zbc_zone_inactive(zone)) {
			*err = "zone is INACTIVE";
			return zbc_set_sense(cmd, DATA_PROTECT,
					     ASC_ZONE_IS_INACTIVE);
		}
		if (zbc_zone_offline(zone)) {
			*err = "zone is OFFLINE";
			return zbc_set_sense(cmd, DATA_PROTECT,
					     ASC_ZONE_IS_OFFLINE);
		}
		if (zbc_zone_rdonly(zone)) {
			*err = "zone is READ ONLY";
			return zbc_set_sense(cmd, DATA_PROTECT,
					     ASC_ZONE_IS_READ_ONLY);
		}
	} else {
		if (zbc_get_zone_domain(zdev, zone) !=
		    zbc_get_zone_domain(zdev, last)) {
			*err = "zone range crosses domain boundary";
			return zbc_set_sense(cmd, ILLEGAL_REQUEST,
					     ASC_INVALID_FIELD_IN_CDB);
		}

		last = &zdev->zones[zdev->nr_zones - 1];
		for (z = zone; count && z <= last; z++, count--) {
			if (zbc_zone_gap(z)) {
				*err = "zone range has GAP zones";
				return zbc_set_sense(cmd, ILLEGAL_REQUEST,
					       ASC_ATTEMPT_TO_ACCESS_GAP_ZONE);
			}
			if (zbc_zone_conv(z)) {
				*err = "zone range has Conventional zones";
				return zbc_set_sense(cmd, ILLEGAL_REQUEST,
						ASC_INVALID_FIELD_IN_CDB);
			}
		}
	}

	*pzone = zone;
	*plast = last;
	return TCMU_STS_OK;
}

/*
 * Close an open zone.
 */
static void __zbc_close_zone(struct zbc_dev *zdev, struct zbc_zone *zone)
{
	if (zbc_zone_conv(zone) || !zbc_zone_is_open(zone))
		return;

	if (zbc_zone_sobr(zone))
		return;

	if (!zbc_zone_seq_req(zone))
		; /* Don't count SWP open zones */
	else if (zbc_zone_imp_open(zone))
		zdev->nr_imp_open--;
	else if (zbc_zone_exp_open(zone))
		zdev->nr_exp_open--;
	else
		tcmu_dev_err(zdev->dev, "Bad SWR close zone_cond 0x%x",
			     zone->cond);

	zbc_unlink_zone(zdev, zone);

	if (zone->wp == zone->start) {
		zone->cond = ZBC_ZONE_COND_EMPTY;
		zbc_add_zone_tail(zdev, zdev->seq_active_zones, zone);
		zdev->nr_empty_zones++;
	} else {
		zone->cond = ZBC_ZONE_COND_CLOSED;
		/*
		 * Add to HEAD of the closed list because this might be an
		 * implicit close during an OPEN ALL of the closed list.
		 */
		zbc_add_zone_head(zdev, zdev->closed_zones, zone);
	}
}

/*
 * Close the first implicitly open zone that decrements the implicit
 * open zone count. Only SWR zones decrement this counter.
 */
static void __zbc_close_imp_open_zone(struct zbc_dev *zdev)
{
	struct zbc_zone *zone, *next;

	zone = zbc_first_zone(zdev, zdev->imp_open_zones);
	for (; zone != NULL; zone = next) {
		next = zbc_next_zone(zdev, zone);
		__zbc_close_zone(zdev, zone);
		if (zdev->nr_imp_open + zdev->nr_exp_open <
		    zdev->nr_open_zones)
			break;
	}
}

/*
 * Close zone command emulation.
 */
static int zbc_close_zone(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			  uint64_t lba, unsigned int count, bool all)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	struct zbc_zone *zone, *z, *next, *last;
	const char *err;
	unsigned int c;
	int ret;

	if (all) {
		if (count) {
			tcmu_dev_warn(dev,
				"ALL bit is set in CLOSE ZONE, count is %i\n",
				count);
			return zbc_set_sense(cmd, ILLEGAL_REQUEST,
					     ASC_INVALID_FIELD_IN_CDB);
		}

		/* Close all open sequential zones */
		for (zone = zbc_first_zone(zdev, zdev->imp_open_zones);
		     zone != NULL;
		     zone = next) {

			next = zbc_next_zone(zdev, zone);
			__zbc_close_zone(zdev, zone);
		}

		for (zone = zbc_first_zone(zdev, zdev->exp_open_zones);
		     zone != NULL;
		     zone = next) {

			next = zbc_next_zone(zdev, zone);
			__zbc_close_zone(zdev, zone);
		}

		if (zdev->nr_imp_open || zdev->nr_exp_open) {
			tcmu_dev_err(dev,
				     "%u implicit, %u explicit still open\n",
				     zdev->nr_imp_open, zdev->nr_exp_open);
		}

		return TCMU_STS_OK;
	}

	/* Check if we can close the specified zone */
	ret = zbc_get_check_zone(zdev, cmd, lba, count, &zone, &last, &err);
	if (ret) {
		tcmu_dev_warn(dev,
			      "CLOSE ZONE %"PRIu64", count %i: %s\n",
			      lba, count, err);
		return ret;
	}

	for (z = zone, c = count; c && z <= last; z++, c--) {
		if (zbc_zone_sobr(z)) {
			tcmu_dev_warn(dev,
				      "Closing SOBR zone %"PRIu64"\n", lba);
			return zbc_set_sense(cmd, ILLEGAL_REQUEST,
					     ASC_INVALID_FIELD_IN_CDB);
		}
	}

	for (; count && zone <= last; zone++, count--) {
		/* Close the specified zone */
		__zbc_close_zone(zdev, zone);
	}

	return TCMU_STS_OK;
}

/*
 * Explicitly or implicitly open a zone.
 */
static void __zbc_open_zone(struct zbc_dev *zdev, struct zbc_zone *zone,
			    bool explicit)
{
	if (zbc_zone_conv(zone) || zbc_zone_inactive(zone) ||
	    zbc_zone_offline(zone) || zbc_zone_rdonly(zone))
		return;

	if (zbc_zone_exp_open(zone) ||
	    (!explicit && zbc_zone_imp_open(zone)))
		return;

	/* Close an implicit open zone if necessary */
	if (zbc_zone_seq_req(zone)) {
		if (zdev->nr_imp_open + zdev->nr_exp_open >=
		    zdev->nr_open_zones)
			__zbc_close_imp_open_zone(zdev);
	}

	zbc_unlink_zone(zdev, zone);
	zbc_on_cond_change(zdev, zone, ZBC_ZONE_COND_EXP_OPEN);

	if (explicit) {
		zone->cond = ZBC_ZONE_COND_EXP_OPEN;
		if (zbc_zone_seq_req(zone))
			zdev->nr_exp_open++;
		zbc_add_zone_tail(zdev, zdev->exp_open_zones, zone);

		if (zdev->nr_exp_open > zdev->max_exp_open_seq_zones)
			zdev->max_exp_open_seq_zones = zdev->nr_exp_open;
	} else {
		zone->cond = ZBC_ZONE_COND_IMP_OPEN;
		if (zbc_zone_seq_req(zone))
			zdev->nr_imp_open++;
		zbc_add_zone_tail(zdev, zdev->imp_open_zones, zone);

		if (zdev->nr_imp_open > zdev->max_imp_open_seq_zones)
			zdev->max_imp_open_seq_zones = zdev->nr_imp_open;
	}
	if (zdev->nr_exp_open + zdev->nr_imp_open > zdev->max_open_zones)
		zdev->max_open_zones = zdev->nr_exp_open + zdev->nr_imp_open;
}

/*
 * Open zone command emulation.
 */
static int zbc_open_zone(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			 uint64_t lba, unsigned int count, bool all)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	struct zbc_zone *zone, *z, *next, *last;
	const char *err;
	unsigned int c, nr_open;
	int ret;

	if (all) {
		unsigned int nr_closed = 0;

		if (count) {
			tcmu_dev_warn(dev,
				"ALL bit is set in OPEN ZONE, count is %u\n",
				count);
			return zbc_set_sense(cmd, ILLEGAL_REQUEST,
					     ASC_INVALID_FIELD_IN_CDB);
		}

		/* Count all SWR closed zones */
		for (zone = zbc_first_zone(zdev, zdev->closed_zones);
		     zone != NULL;
		     zone = zbc_next_zone(zdev, zone)) {
			if (zbc_zone_seq_req(zone))
				nr_closed++;
		}

		/* Check if all SWR closed zones can be open */
		if (!zbc_ozr_check(zdev, nr_closed)) {
			zdev->failed_exp_opens++;
			return zbc_set_sense(cmd, DATA_PROTECT,
					     ASC_INSUFFICIENT_ZONE_RESOURCES);
		}

		/* Open all zones closed at the time loop commences */
		for (zone = zbc_first_zone(zdev, zdev->closed_zones);
		     zone != NULL;
		     zone = next) {
			next = zbc_next_zone(zdev, zone);
			__zbc_open_zone(zdev, zone, true);
		}

		return TCMU_STS_OK;
	}

	/* Check if we can open the specified zone */
	ret = zbc_get_check_zone(zdev, cmd, lba, count, &zone, &last, &err);
	if (ret) {
		zdev->failed_exp_opens++;
		tcmu_dev_warn(dev,
			      "OPEN ZONE %"PRIu64", count %i: %s\n",
			      lba, count, err);
		return ret;
	}

	/* Check if we are going to encounter errors throughout the range */
	nr_open = 0;
	for (z = zone, c = count; c && z <= last; z++, c--) {
		if (zbc_zone_sobr(z)) {
			tcmu_dev_warn(dev,
				      "Opening SOBR zone %"PRIu64"\n", lba);
			return zbc_set_sense(cmd, ILLEGAL_REQUEST,
					     ASC_INVALID_FIELD_IN_CDB);
		}

		if (zbc_zone_exp_open(z) || zbc_zone_full(z))
			continue;

		if (zbc_zone_seq_req(z)) {
			nr_open++;
			if (!zbc_ozr_check(zdev, nr_open)) {
				zdev->failed_exp_opens++;
				return zbc_set_sense(cmd, DATA_PROTECT,
					ASC_INSUFFICIENT_ZONE_RESOURCES);
			}
		}
	}

	/* Open the specified zone(s) */
	for (; count && zone <= last; zone++, count--) {
		if (zbc_zone_exp_open(zone) || zbc_zone_full(zone))
			continue;

		if (zbc_zone_imp_open(zone))
			__zbc_close_zone(zdev, zone);

		__zbc_open_zone(zdev, zone, true);
	}

	return TCMU_STS_OK;
}

/*
 * Finish a zone.
 */
static void __zbc_finish_zone(struct zbc_dev *zdev, struct zbc_zone *zone,
			      bool empty)
{
	if (zbc_zone_conv(zone) || zbc_zone_inactive(zone) ||
	    zbc_zone_offline(zone) || zbc_zone_rdonly(zone))
		return;

	if (zbc_zone_closed(zone) ||
	    zbc_zone_is_open(zone) ||
	    (empty && zbc_zone_empty(zone))) {
		if (zbc_zone_is_open(zone))
			__zbc_close_zone(zdev, zone);

		zbc_on_cond_change(zdev, zone, ZBC_ZONE_COND_FULL);

		zbc_unlink_zone(zdev, zone);

		if (zbc_zone_sobr(zone))
			zone->wp = ZBC_NO_WP;
		else
			zone->wp = zone->start + zone->len;
		zone->cond = ZBC_ZONE_COND_FULL;
		zbc_add_zone_tail(zdev, zdev->seq_active_zones, zone);
		zone->non_seq = 0;
		zone->reset = 0;
	}
}

/*
 * Finish zone command emulation.
 */
static int zbc_finish_zone(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			   uint64_t lba, unsigned int count, bool all)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	struct zbc_zone *zone, *z, *next, *last;
	const char *err;
	unsigned int c;
	int ret;

	if (all) {
		if (count) {
			tcmu_dev_warn(dev,
				"ALL bit is set in FINISH ZONE, count is %u\n",
				count);
			return zbc_set_sense(cmd, ILLEGAL_REQUEST,
					     ASC_INVALID_FIELD_IN_CDB);
		}

		/* Finish all open and closed zones */
		for (zone = zbc_first_zone(zdev, zdev->imp_open_zones);
		     zone != NULL;
		     zone = next) {
			next = zbc_next_zone(zdev, zone);
			__zbc_finish_zone(zdev, zone, false);
		}

		for (zone = zbc_first_zone(zdev, zdev->exp_open_zones);
		     zone != NULL;
		     zone = next) {
			next = zbc_next_zone(zdev, zone);
			__zbc_finish_zone(zdev, zone, false);
		}

		for (zone = zbc_first_zone(zdev, zdev->closed_zones);
		     zone != NULL;
		     zone = next) {
			next = zbc_next_zone(zdev, zone);
			__zbc_finish_zone(zdev, zone, false);
		}

		return TCMU_STS_OK;
	}

	/* Check if we have a valid start zone to finish */
	ret = zbc_get_check_zone(zdev, cmd, lba, count, &zone, &last, &err);
	if (ret) {
		tcmu_dev_warn(dev,
			      "FINISH ZONE %"PRIu64", count %i: %s\n",
			      lba, count, err);
		return ret;
	}

	/* Check if we can finish all the specified zones */
	for (z = zone, c = count; c && z <= last; z++, c--) {
		if (zbc_zone_inactive(z)) {
			tcmu_dev_warn(dev,
				      "Finishing INACTIVE zone %"PRIu64"\n",
				      lba);
			return zbc_set_sense(cmd, DATA_PROTECT,
					     ASC_ZONE_IS_INACTIVE);
		}
		if (zbc_zone_offline(z)) {
			tcmu_dev_warn(dev,
				      "Finishing OFFLINE zone %"PRIu64"\n",
				      lba);
			return zbc_set_sense(cmd, DATA_PROTECT,
					     ASC_ZONE_IS_OFFLINE);
		}
		if (zbc_zone_rdonly(z)) {
			tcmu_dev_warn(dev,
				      "Finishing RDONLY zone %"PRIu64"\n",
				      lba);
			return zbc_set_sense(cmd, DATA_PROTECT,
					     ASC_ZONE_IS_READ_ONLY);
		}
		if (zbc_zone_seq_req(z) &&
		    (zbc_zone_closed(z) || zbc_zone_empty(z))) {
			if (!zbc_ozr_check(zdev, 1))
				return zbc_set_sense(cmd, DATA_PROTECT,
					ASC_INSUFFICIENT_ZONE_RESOURCES);
		}
	}

	/* Finish the specified zone(s) */
	for (; count && zone <= last; zone++, count--)
		__zbc_finish_zone(zdev, zone, true);

	return TCMU_STS_OK;
}

/*
 * Reset a zone.
 */
static void __zbc_reset_wp(struct zbc_dev *zdev, struct zbc_zone *zone)
{
	if (zbc_zone_is_open(zone))
		__zbc_close_zone(zdev, zone);

	if (zbc_zone_inactive(zone) || zbc_zone_offline(zone) ||
	    zbc_zone_rdonly(zone)) {
		zone->wp = ZBC_NO_WP;
	} else if (zbc_zone_conv(zone)) {
		zone->cond = ZBC_ZONE_COND_NOT_WP;
		zone->wp = ZBC_NO_WP;
	} else if (!zbc_zone_empty(zone)) {
		zbc_unlink_zone(zdev, zone);
		zone->cond = ZBC_ZONE_COND_EMPTY;
		zone->wp = zone->start;
		zbc_add_zone_head(zdev, zdev->seq_active_zones, zone);
		zdev->nr_empty_zones++;
	}

	zone->non_seq = 0;
	zone->reset = 0;
}

/*
 * Reset write pointer command emulation.
 */
static int zbc_reset_wp(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			uint64_t lba, unsigned int count, bool all)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	struct zbc_zone *zone, *next, *last;
	const char *err;
	int ret;

	if (all) {
		if (count) {
			tcmu_dev_warn(dev,
				"ALL bit is set in RESET ZONE, count is %u\n",
				count);
			return zbc_set_sense(cmd, ILLEGAL_REQUEST,
					     ASC_INVALID_FIELD_IN_CDB);
		}

		/* Reset all zones */
		for (zone = zbc_first_zone(zdev, zdev->seq_active_zones);
		     zone != NULL;
		     zone = next) {
			next = zbc_next_zone(zdev, zone);
			__zbc_reset_wp(zdev, zone);
		}

		for (zone = zbc_first_zone(zdev, zdev->imp_open_zones);
		     zone != NULL;
		     zone = next) {
			next = zbc_next_zone(zdev, zone);
			__zbc_reset_wp(zdev, zone);
		}

		for (zone = zbc_first_zone(zdev, zdev->exp_open_zones);
		     zone != NULL;
		     zone = next) {
			next = zbc_next_zone(zdev, zone);
			__zbc_reset_wp(zdev, zone);
		}

		for (zone = zbc_first_zone(zdev, zdev->closed_zones);
		     zone != NULL;
		     zone = next) {
			next = zbc_next_zone(zdev, zone);
			__zbc_reset_wp(zdev, zone);
		}

		if (zdev->nr_imp_open || zdev->nr_exp_open) {
			tcmu_dev_err(dev,
				     "%u implicit, %u explicit still open\n",
				     zdev->nr_imp_open, zdev->nr_exp_open);
		}

		return TCMU_STS_OK;
	}

	/* Check if we can reset the zone */
	ret = zbc_get_check_zone(zdev, cmd, lba, count, &zone, &last, &err);
	if (ret) {
		tcmu_dev_warn(dev,
			      "RESET WP, LBA %"PRIu64", count %i: %s\n",
			      lba, count, err);
		return ret;
	}

	/* Reset the write pointer in specified zone(s) */
	for (; count && zone <= last; zone++, count--)
		__zbc_reset_wp(zdev, zone);

	return TCMU_STS_OK;
}

/*
 * Sequentialize a zone.
 * Sets Non-Sequential Write Resources Active zone attribute to false.
 *		-- ZBC-2 4.4.3.2.8 (Draft May 4, 2018)
 */
static void __zbc_sequentialize_zone(struct zbc_dev *zdev,
				     struct zbc_zone *zone)
{
	zone->non_seq = 0;
}

/*
 * Sequentialize zone command emulation.
 */
static int zbc_sequentialize_zone(struct tcmu_device *dev,
				  struct tcmulib_cmd *cmd, uint64_t lba,
				  unsigned int count, bool all)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	struct zbc_zone *zone, *z, *next, *last;
	const char *err;
	unsigned int c;
	int ret;

	if (all) {
		if (count) {
			tcmu_dev_warn(dev,
				"ALL bit set in SEQ-IZE ZONE, count is %u\n",
				count);
			return zbc_set_sense(cmd, ILLEGAL_REQUEST,
					     ASC_INVALID_FIELD_IN_CDB);
		}

		/* Sequentialize all closed zones */
		for (zone = zbc_first_zone(zdev, zdev->closed_zones);
		     zone != NULL;
		     zone = next) {
			next = zbc_next_zone(zdev, zone);
			__zbc_sequentialize_zone(zdev, zone);
		}

		return TCMU_STS_OK;
	}

	/* Check if we a valid start zone */
	ret = zbc_get_check_zone(zdev, cmd, lba, count, &zone, &last, &err);
	if (ret) {
		tcmu_dev_warn(dev,
			      "SEQUENTIALIZE ZONE %"PRIu64", count %i: %s\n",
			      lba, count, err);
		return ret;
	}

	/* Make sure all the specified zones are SWP */
	for (z = zone, c = count; c && z <= last; z++, c--) {
		if (!zbc_zone_seq_pref(z))
			return zbc_set_sense(cmd, ILLEGAL_REQUEST,
					ASC_INVALID_FIELD_IN_CDB);
	}

	/* Sequentialize the specified zone(s) */
	for (; count && zone <= last; zone++, count--) {
		if (!zbc_zone_empty(zone))
			__zbc_sequentialize_zone(zdev, zone);
	}

	return TCMU_STS_OK;
}

/*
 * An activation descriptor list item. It carries both activation and
 * deactivation descriptors for a single realm. The realm activation code
 * allocates and adds one of these to the list of activation results.
 * If the activation is done successfully, all the descriptors are added
 * to the command output.
 */
struct zbc_actv_desc_list {
	struct zbc_actv_desc_list *next;
	uint8_t first[ZBC_ACTV_RES_DESCRIPTOR_SIZE];
	uint8_t second[ZBC_ACTV_RES_DESCRIPTOR_SIZE];
};

/*
 * Zone Activation results.
 */
struct zbc_za_results {
	struct zbc_actv_desc_list *recs; /* Activation record list head */
	struct zbc_actv_desc_list *tail; /* Activation record list tail */
	uint64_t	ziwup; /* Zone ID with unmet prerequisites */
	uint32_t	nr_desc; /* Number of activation results descriptors */
	uint32_t	error; /* Error bits (unmet prerequisites) */

};

/*
 * Init activation results.
 */
static inline void zbc_init_actv_results(struct zbc_za_results *actv_res)
{
	actv_res->recs = NULL;
	actv_res->tail = NULL;
	actv_res->ziwup = ULLONG_MAX;
	actv_res->nr_desc = 0;
	actv_res->error = 0;
}

/*
 * Allocate new activation record list item and link it with the results.
 * Returns the list item if allocated, otherwise NULL.
 */
static inline
struct zbc_actv_desc_list *zbc_alloc_actv_desc(struct zbc_za_results *actv_res)
{
	struct zbc_actv_desc_list *desc;

	desc = calloc(1, sizeof(struct zbc_actv_desc_list));
	if (desc) {
		if (!actv_res->recs) {
			actv_res->recs = desc;
			actv_res->tail = desc;
		} else {
			actv_res->tail->next = desc;
			actv_res->tail = desc;
		}
	}

	return desc;
}

/*
 * Cleanup activation results.
 */
static inline void zbc_cleanup_actv_results(struct zbc_za_results *actv_res)
{
	struct zbc_actv_desc_list *recs, *next;

	for (recs = actv_res->recs; recs != NULL; recs = next) {
		next = recs->next;
		free(recs);
	}
	actv_res->recs = NULL;
	actv_res->tail = NULL;
}

/*
 * Fill the input buffer with an activation results descriptor for a realm.
 */
static void zbc_fill_actv_record(struct zbc_dev *zdev,
				 struct zbc_zone_realm *r,
				 struct zbc_zone *zone, unsigned int cond,
				 uint32_t nr_zones, uint8_t *buf)
{
	/* Populate activation result descriptor */
	memset(buf, 0, ZBC_ACTV_RES_DESCRIPTOR_SIZE);
	buf[0] = zone->type;
	buf[1] = cond << 4;
	buf[2] = zbc_get_zone_domain(zdev, zone);
	zbc_cpbe64(&buf[8], nr_zones);
	zbc_cpbe64(&buf[16], zone->start);
}

static inline int zbc_cmr_to_smr_zones(struct zbc_dev *zdev,
				       unsigned int cmr_zones)
{
	if (!cmr_zones)
		return -1;
	return zdev->cmr_nr_zones_to_smr[cmr_zones - 1];
}

static inline int zbc_smr_to_cmr_zones(struct zbc_dev *zdev,
				       unsigned int smr_zones)
{
	if (!smr_zones)
		return -1;
	return zdev->smr_nr_zones_to_cmr[smr_zones - 1];
}

static int zbc_get_deactv_realm_zones(struct zbc_dev *zdev,
				      struct zbc_zone_realm *r,
				      unsigned int offset, unsigned int length,
				      unsigned int new_type)
{
	int old_dom, new_dom;

	if (r->type != new_type) {
		old_dom = zbc_domain_id(zdev, r->type);
		new_dom = zbc_domain_id(zdev, new_type);
		if (old_dom < 0 || new_dom < 0)
			return -1;
		if (zbc_smr_domain(&zdev->domains[old_dom]) &&
		    !zbc_smr_domain(&zdev->domains[new_dom]))
			length = zbc_cmr_to_smr_zones(zdev, length);
		else if (!zbc_smr_domain(&zdev->domains[old_dom]) &&
			 zbc_smr_domain(&zdev->domains[new_dom]))
			length = zbc_smr_to_cmr_zones(zdev, length);
	}

	return min(zbc_realm_length(r, r->type) - offset, length);
}

/*
 * Check if the specified realm can be activated to the new type.
 */
static bool zbc_chk_can_actv_realm(struct zbc_dev *zdev,
				   struct zbc_zone_realm *r,
				   unsigned int offset, unsigned int length,
				   unsigned int new_type, bool all,
				   struct zbc_za_results *actv_res)
{
	struct tcmu_device *dev = zdev->dev;
	struct zbc_zone *zone;
	uint64_t ziwup = ULLONG_MAX;
	unsigned int err = 0, i, nr_zones;
	bool have_zt;

	if (!all && !zbc_can_actv_realm_as(r, new_type)) {

		tcmu_dev_warn(dev,
			      "Activate realm %u to type 0x%x disallowed\n",
			      r->number, new_type);
		err = ZBC_ACTV_ERR_UNSUPP;
		ziwup = zbc_realm_start(r, r->type);

	} else if ((zbc_realm_nowp(r) &&
		    zbc_act_type_sobr(new_type)) ||
		   (zbc_realm_sobr(r) &&
		    zbc_act_type_nowp(new_type))) {

		/* NOT WP zones are not in ZD standard, still enforce these */
		tcmu_dev_warn(dev,
			"Can't activate realm %u (type 0x%x) to type 0x%x\n",
			r->number, r->type, new_type);
		err = ZBC_ACTV_ERR_UNSUPP;
		ziwup = zbc_realm_start(r, r->type);
	} else if ((zbc_realm_seq_p(r) &&
		    zbc_act_type_seq_r(new_type)) ||
		   (zbc_realm_seq_r(r) &&
		    zbc_act_type_seq_p(new_type))) {

		/* FIXME Same, this might be allowed per new spec */
		tcmu_dev_warn(dev,
			"Can't activate realm %u (type 0x%x) to type 0x%x\n",
			r->number, r->type, new_type);
		err = ZBC_ACTV_ERR_UNSUPP;
		ziwup = zbc_realm_start(r, r->type);
	}
	if (err)
		goto out;

	/*
	 * Fail if there are zones with active WP in
	 * the zone range that is being deactivated.
	 */
	zone = zbc_realm_start_zone(zdev, r, r->type);
	zone += offset;
	nr_zones = zbc_get_deactv_realm_zones(zdev, r, offset,
					      length, new_type);

	if (all) {
		have_zt = false;
		for (i = 0; i < nr_zones; i++, zone++) {
			if (zbc_zone_closed(zone) ||
			    zbc_zone_exp_open(zone) ||
			    zbc_zone_imp_open(zone) ||
			    zbc_zone_full(zone))
				break;
			if (zbc_zone_empty(zone) ||
			    zbc_zone_inactive(zone)) /* FIXME allow for test */
				have_zt = true;
		}
		if (i < nr_zones) {
			tcmu_dev_warn(dev,
				"Realm %u not empty, zone %llu, cond 0x%x\n",
				r->number, zone->start, zone->cond);
			err = ZBC_ACTV_ERR_NOT_EMPTY;
			ziwup = zone->start;
			goto out;
		} else if (!have_zt) {
			tcmu_dev_warn(dev, "No empty zones in realm %u\n",
				      r->number);
			err = ZBC_ACTV_ERR_NOT_EMPTY;
			goto out;
		}
	} else {
		for (i = 0; i < nr_zones; i++, zone++) {
			if (!zbc_zone_conv(zone) && /* Pass conventional */
			    !zbc_zone_empty(zone) &&
			    !zbc_zone_inactive(zone)) /* FIXME for test */
				break;
		}
		if (i < nr_zones) {
			tcmu_dev_warn(dev,
				"Zone %llu of realm %u not empty, cond 0x%x\n",
				zone->start, r->number, zone->cond);
			err = ZBC_ACTV_ERR_NOT_EMPTY;
			ziwup = zone->start;
			goto out;
		}
	}

	if (!zbc_can_actv_realm_as(r, new_type))
		goto out; /* Can only happen if ALL is set */

	/*
	 * Fail if there are active zones in the
	 * zone range that is being activated.
	 */
	zone = zbc_realm_start_zone(zdev, r, new_type);
	zone += offset;
	nr_zones = min(zbc_realm_length(r, new_type) - offset, length);

	if (all) {
		have_zt = false;
		for (i = 0; i < nr_zones; i++, zone++) {
			if (zbc_zone_imp_open(zone) ||
			    zbc_zone_full(zone))
				break;
			if (zbc_zone_inactive(zone) ||
			    zbc_zone_empty(zone)) /* FIXME allow for test */
				have_zt = true;
		}
		if (i < nr_zones) {
			tcmu_dev_warn(dev,
				"Realm %u active, zone %llu, cond 0x%x\n",
				r->number, zone->start, zone->cond);
			err = ZBC_ACTV_ERR_NOT_INACTIVE;
			ziwup = zone->start;
			goto out;
		} else if (!have_zt) {
			tcmu_dev_warn(dev, "No inactive zones in realm %u\n",
				      r->number);
			err = ZBC_ACTV_ERR_NOT_INACTIVE;
			goto out;
		}
	} else {
		for (i = 0; i < nr_zones; i++, zone++) {
			if (!zbc_zone_conv(zone) && /* Pass conventional */
			    !zbc_zone_empty(zone) &&
			    !zbc_zone_rdonly(zone) &&
			    !zbc_zone_offline(zone) &&
			    !zbc_zone_inactive(zone)) /* FIXME allow for test */
				break;
		}
		if (i < nr_zones) {
			tcmu_dev_warn(dev,
				"Zone %llu of realm %u is active, cond 0x%x\n",
				zone->start, r->number, zone->cond);
			err = ZBC_ACTV_ERR_NOT_INACTIVE;
			ziwup = zone->start;
			goto out;
		}
	}

out:
	if (err) {
		actv_res->ziwup = ziwup;
		actv_res->error |= err;
		return false;
	}

	return true;
}

/*
 * Put the current zones of the realm to INACTIVE condition.
 */
static void zbc_deactivate_realm_zones(struct zbc_dev *zdev,
				       struct zbc_zone_realm *r,
				       unsigned int offset,
				       unsigned int length,
				       unsigned int new_type,
				       bool dry_run, uint8_t *buf)
{
	struct zbc_zone *zone;
	unsigned int i, nr_zones, cond;

	zone = zbc_realm_start_zone(zdev, r, r->type);
	nr_zones = zbc_realm_length(r, r->type);

	if (new_type == r->type) {
		dry_run = true;
		cond = zone->cond;
	} else {
		cond = ZBC_ZONE_COND_INACTIVE;
	}

	zbc_fill_actv_record(zdev, r, zone, cond, nr_zones, buf);

	if (!dry_run) {
		for (i = 0; i < nr_zones; i++, zone++) {
			if (zbc_zone_rdonly(zone) || zbc_zone_offline(zone))
				continue;
			zbc_unlink_zone(zdev, zone);
			zbc_on_cond_change(zdev, zone, cond);

			zone->cond = cond;
			zbc_set_initial_wp(zdev, zone);
		}
	}
}

/*
 * Activate zones of the realm's new type.
 */
static void zbc_activate_realm_zones(struct zbc_dev *zdev,
				     struct zbc_zone_realm *r,
				     unsigned int offset, unsigned int length,
				     unsigned int new_type, bool dry_run,
				     uint8_t *buf)
{
	struct zbc_zone *zone;
	unsigned int i, nr_zones;
	unsigned int cond;

	zone = zbc_realm_start_zone(zdev, r, new_type);
	nr_zones = zbc_realm_length(r, new_type);

	if (new_type == r->type) {
		dry_run = true;
		cond = zone->cond;
	}
	else if (zbc_act_type_nowp(new_type))
		cond = ZBC_ZONE_COND_NOT_WP;
	else
		cond = ZBC_ZONE_COND_EMPTY;

	zbc_fill_actv_record(zdev, r, zone, cond, nr_zones, buf);

	if (!dry_run) {
		for (i = 0; i < nr_zones; i++, zone++) {
			if (zbc_zone_rdonly(zone) || zbc_zone_offline(zone))
				continue;
			zbc_unlink_zone(zdev, zone);
			if (zone->cond != ZBC_ZONE_COND_EMPTY &&
			    cond == ZBC_ZONE_COND_EMPTY)
				zdev->nr_empty_zones++;
			zone->cond = cond;
			zbc_set_initial_wp(zdev, zone);
		}
	}
}

/*
 * Activate one realm to a new type.
 */
static int zbc_activate_realm(struct zbc_dev *zdev, struct zbc_zone_realm *r,
			      unsigned int offset, unsigned int length,
			      unsigned int new_type, bool dry_run, bool all,
			      struct zbc_za_results *actv_res)
{
	struct zbc_actv_desc_list *actv_desc;
	uint64_t rs_old, rs_new;
	bool deac_1st;

	if (!zbc_chk_can_actv_realm(zdev, r, offset, length,
				    new_type, all, actv_res))
		return 1;

	if (!zbc_can_actv_realm_as(r, new_type)) {
		/*
		 * Get here only if ALL. FIXME should we still output
		 * activation results for this one?
		 */
		return 0;
	}

	actv_desc = zbc_alloc_actv_desc(actv_res);
	if (!actv_desc)
		return -1;

	rs_old = zbc_realm_start(r, r->type);
	rs_new = zbc_realm_start(r, new_type);
	deac_1st = rs_old < rs_new;
	if (rs_old != rs_new)
		actv_res->nr_desc++;

	zbc_deactivate_realm_zones(zdev, r, offset, length, new_type, dry_run,
			deac_1st ? actv_desc->first : actv_desc->second);
	actv_res->nr_desc++;

	zbc_activate_realm_zones(zdev, r, offset, length, new_type, dry_run,
			deac_1st ? actv_desc->second : actv_desc->first);

	/* Set the new realm type */
	if (!dry_run)
		r->type = new_type;

	return 0;
}

static int zbc_zone_activate(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			     uint64_t start_lba, unsigned int nr_zones,
			     unsigned int domain_id, unsigned int alloc_len,
			     bool all, bool nozsrc, bool dry_run)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	struct zbc_zone_domain *d;
	struct zbc_zone *zone, *end_zone;
	struct zbc_actv_desc_list *desc;
	uint8_t *actv_rec;
	struct iovec *iovec = cmd->iovec;
	uint64_t ofs;
	size_t iov_cnt = cmd->iov_cnt;
	struct zbc_za_results actv_res;
	unsigned int new_type, addr_zt;
	int i, ret, nz, sz, start_realm, end, len;
	uint8_t actv_rec_hdr[ZBC_ACTV_RES_HEADER_SIZE];
	uint8_t status = 0;
	bool ok = false;

	/* Validate the the domain ID to activate */
	if (domain_id >= zdev->nr_domains) {
		tcmu_dev_warn(dev,
			      "Device doesn't support domain ID %u\n",
			      domain_id);
		goto illreq;
	}
	d = &zdev->domains[domain_id];

	/*
	 * If ALL is set, forget start_lba and nr_zones and set them
	 * to cover the whole domain specified by the incomin domain ID.
	 */
	if (all) {
		start_lba = d->start_lba;
		nr_zones = d->nr_zones;
	}

	/* No zones, no go */
	if (!nr_zones) {
		tcmu_dev_warn(dev,
			      "No zones to activate\n");
		goto illreq;
	}
	if (nr_zones > zdev->nr_zones) {
		tcmu_dev_warn(dev,
			      "%u zones to activate exceeds %u zone total\n",
			      nr_zones, zdev->nr_zones);
		goto illreq;
	}

	/* Check if allocated length is enough to fit at least the header */
	if (alloc_len < ZBC_ACTV_RES_HEADER_SIZE) {
		tcmu_dev_warn(dev, "Allocated length %u is too small\n",
			      alloc_len);
		goto illreq;
	}

	/* Validate the activation range */
	zone = zbc_get_zone(zdev, start_lba, true);
	if (!zone) {
		tcmu_dev_dbg(dev,
			     "Activation LBA %"PRIu64" not aligned to zone\n",
			     start_lba);
		goto illreq;
	}
	if (zone - zdev->zones > zdev->nr_zones - nr_zones) {
		tcmu_dev_warn(dev,
			      "Activation %"PRIu64"+%u out of LBA range\n",
			      start_lba, nr_zones);
		goto illreq;
	}
	i = zbc_get_zone_domain(zdev, zone);
	if (i < 0) {
		tcmu_dev_dbg(dev,
			     "Activation start zone %"PRIu64" not in domain\n",
			     start_lba);
		goto illreq;
	}
	/*
	 * All further errors will be reported by setting
	 * status bits in the activation results header.
	 */

	zbc_init_actv_results(&actv_res);

	/* Initialize the activation results header */
	memset(&actv_rec_hdr, 0, sizeof(actv_rec_hdr));
	actv_rec_hdr[10] = domain_id;
	if (nozsrc)
		actv_rec_hdr[12] |= 0x02; /* NOZSRC */
	if (all) {
		actv_rec_hdr[12] |= 0x01; /* All */
	} else {
		/* Set NZP validity bit and the number of zones */
		nz = nr_zones;
		status |= ZBC_ACTV_STAT_NZP_VALID;
		zbc_cpbe32(&actv_rec_hdr[16], nz);
	}

	/* Find the starting realm and check for domain cross-over */
	start_realm = zbc_get_zone_realm(zdev, start_lba,
					 zdev->realms_feat_set && !all,
					 &addr_zt);
	if (start_realm < 0) {
		tcmu_dev_warn(dev,
			      "Invalid zone activation LBA %"PRIu64"\n",
			      start_lba);
		actv_res.error |= ZBC_ACTV_ERR_REALM_ALIGN;
		actv_res.ziwup = start_lba;
		goto outhdr;
	}

	/*
	 * Determine the zone type to activate (ZDr2 5.2.102.2.2).
	 * FIXME What if the first zone is offline or read-only?
	 */
	if (all || !zbc_zone_inactive(zone))
		new_type = d->type;
	else
		new_type = addr_zt;

	/* Check if the the specified zone range crosses domain boundary */
	end_zone = zone + nr_zones - 1;
	end = zbc_get_zone_domain(zdev, end_zone);
	if (i != end) {
		tcmu_dev_warn(dev, "Activation range %"PRIu64
				   "+%u crosses domain %u to %i\n",
			      start_lba, nr_zones, i, end);
		actv_res.error |= ZBC_ACTV_ERR_MULTI_DOMAINS;
		actv_res.ziwup = start_lba;
		goto outhdr;
	}

	if (!zdev->realms_feat_set) {
		/* Find zone offset in the first realm for the start LBA */
		ofs = zone->start;
		ofs -= zbc_realm_start(&zdev->realms[start_realm], zone->type);
		ofs >>= zdev->zone_log2;
	} else
		ofs = 0LL;

	/*
	 * Find the ending realm for this activation, verify
	 * that the range is aligned to realm boundary.
	 */
	end = start_realm;
	nz = nr_zones;
	i = zbc_domain_id(zdev, addr_zt);
	sz = zbc_smr_domain(&zdev->domains[i]) ?
			zdev->nr_smr_realm_zones : zdev->nr_cmr_realm_zones;
	if (ofs != 0LL) {
		nz -= sz - ofs;
		end++;
	}
	for (; end < zdev->nr_realms && nz > 0; end++)
		nz -= sz;
	if (zdev->realms_feat_set && nz != 0) {
		tcmu_dev_warn(dev, "Activation range %"PRIu64
				   "+%u is off by %i zones\n",
			      start_lba, nr_zones, -nz);
		actv_res.error |= ZBC_ACTV_ERR_REALM_ALIGN;
		actv_res.ziwup = start_lba;
		goto outhdr;
	}

	/*
	 * Now, activate or query every realm and collect
	 * all the activation results descriptors.
	 */
	ok = true;
	nz = nr_zones;
	for (i = start_realm; i < end; i++) {
		ret = zbc_activate_realm(zdev, &zdev->realms[i],
					 (unsigned int)ofs, min(nz, sz),
					 new_type, dry_run, all, &actv_res);
		if (ret < 0) {
			tcmu_dev_err(dev, "Can't activate realm #%i\n", i);
			return zbc_set_sense(cmd, HARDWARE_ERROR,
					     ASC_INTERNAL_TARGET_FAILURE);
		}
		if (ret) {
			ok = false;
			break;
		}
		nz -= sz - ofs;
		ofs = 0LL;
	}

outhdr:
	/* Set the status in the header along with ZIWUP if needed */
	len = alloc_len - ZBC_ACTV_RES_HEADER_SIZE;
	sz = actv_res.nr_desc * ZBC_ACTV_RES_DESCRIPTOR_SIZE;
	zbc_cpbe32(&actv_rec_hdr[0], sz);
	zbc_cpbe32(&actv_rec_hdr[4], min(sz, len));
	if (ok) {
		if (!dry_run)
			status |= ZBC_ACTV_STAT_ACTIVATED;
	} else if (actv_res.ziwup != ULLONG_MAX) {
		/* Set ZIWUP validity bit and the zone ID value */
		status |= ZBC_ACTV_STAT_ZIWUP_VALID;
		zbc_cpbe48(&actv_rec_hdr[24], actv_res.ziwup);
	}
	actv_rec_hdr[8] = status;
	actv_rec_hdr[9] = actv_res.error;

	/* Output the header */
	sz = tcmu_memcpy_into_iovec(iovec, iov_cnt, actv_rec_hdr,
				    ZBC_ACTV_RES_HEADER_SIZE);
	if (!ok || sz < ZBC_ACTV_RES_HEADER_SIZE)
		goto out;

	/*
	 * The activate/query operation was successful, output all
	 * the activation records in ascending zone ID order. Since
	 * the activation code puts the record with the lower zone ID
	 * into "first" record of the descriptor, we just need to run
	 * through the descriptor list twice.
	 */
	len = tcmu_iovec_length(iovec, iov_cnt);
	i = actv_res.nr_desc;
	for (desc = actv_res.recs; desc; desc = desc->next, i--) {
		if (len < ZBC_ACTV_RES_DESCRIPTOR_SIZE)
			break;
		actv_rec = desc->first;
		sz = tcmu_memcpy_into_iovec(iovec, iov_cnt, actv_rec,
				       ZBC_ACTV_RES_DESCRIPTOR_SIZE);
		len -= sz;
	}

	for (desc = actv_res.recs; i && desc; desc = desc->next, i--) {
		if (len < ZBC_ACTV_RES_DESCRIPTOR_SIZE)
			break;
		actv_rec = desc->second;
		sz = tcmu_memcpy_into_iovec(iovec, iov_cnt, actv_rec,
				       ZBC_ACTV_RES_DESCRIPTOR_SIZE);
		len -= sz;
	}

out:
	zbc_cleanup_actv_results(&actv_res);
	return TCMU_STS_OK;

illreq:
	return zbc_set_sense(cmd, ILLEGAL_REQUEST,
			     ASC_INVALID_FIELD_IN_CDB);
}

/*
 * SCSI-specific ZONE ACTIVATE(16)/ZONE QUERY(16) command handler.
 */
static int zbc_scsi_zone_activate16(struct tcmu_device *dev,
				    struct tcmulib_cmd *cmd, bool dry_run)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	const struct zbc_dev_features *f = zdev->dev_feat;
	uint8_t *cdb = cmd->cdb;
	uint64_t start_lba;
	uint32_t len, domain_id, nr_zones;
	bool all, nozsrc = false;

	all = cdb[2] & 0x80; /* All */
	domain_id = cdb[2] & 0x3f;
	start_lba = zbc_rdbe48(&cdb[3]);
	len = zbc_rdbe32(&cdb[9]);
	if (cdb[2] & 0x40) { /* NOZSRC */
		if (f->no_nozsrc) {
			tcmu_dev_warn(dev, "NOZSRC bit is not suppported\n");
			return zbc_set_sense(cmd, ILLEGAL_REQUEST,
					     ASC_INVALID_FIELD_IN_CDB);
		}
		nozsrc = true;
		nr_zones = zbc_rdbe16(&cdb[13]);
	} else {
		nr_zones = zdev->nr_actv_zones;
	}

	return zbc_zone_activate(dev, cmd, start_lba, nr_zones,
				 domain_id, len, all, nozsrc, dry_run);
}

/*
 * SCSI-specific ZONE ACTIVATE(32)/ZONE QUERY(32) command handler.
 */
static int zbc_scsi_zone_activate32(struct tcmu_device *dev,
				    struct tcmulib_cmd *cmd)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	const struct zbc_dev_features *f = zdev->dev_feat;
	uint8_t *cdb = cmd->cdb;
	uint64_t start_lba;
	uint32_t len, sa, domain_id, nr_zones;
	bool all, dry_run, nozsrc = false;

	if (cdb[7] != 0x18) {
		tcmu_dev_warn(dev, "Wrong zone activation CDB length 0x%x\n",
			      cdb[7]);
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_INVALID_FIELD_IN_CDB);
	}
	sa = zbc_rdbe16(&cdb[8]);
	switch (sa) {
	case ZBC_SA_ZONE_ACTIVATE_32:
		dry_run = false;
		break;
	case ZBC_SA_ZONE_QUERY_32:
		dry_run = true;
		break;
	default:
		tcmu_dev_warn(dev, "Invalid ACTIVATION IN (32) SA 0x%x\n", sa);
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_INVALID_FIELD_IN_CDB);
	}

	all = cdb[10] & 0x80;
	domain_id = cdb[11];
	start_lba = zbc_rdbe64(&cdb[12]);
	len = zbc_rdbe32(&cdb[28]);
	if (cdb[10] & 0x40) { /* NOZSRC */
		if (f->no_nozsrc) {
			tcmu_dev_warn(dev, "NOZSRC bit is not suppported\n");
			return zbc_set_sense(cmd, ILLEGAL_REQUEST,
					     ASC_INVALID_FIELD_IN_CDB);
		}
		nozsrc = true;
		nr_zones = zbc_rdbe32(&cdb[20]);
	} else {
		nr_zones = zdev->nr_actv_zones;
	}

	return zbc_zone_activate(dev, cmd, start_lba, nr_zones,
				 domain_id, len, all, nozsrc, dry_run);
}

/*
 * Report all the mutation types supported by the device.
 */
static int zbc_report_mutations(struct tcmu_device *dev,
				struct tcmulib_cmd *cmd, size_t len)
{
	const struct zbc_dev_features *f = zbc_opt_feat;
	struct iovec *iovec = cmd->iovec;
	size_t iov_cnt = cmd->iov_cnt;
	int i, nr_recs = ARRAY_SIZE(zbc_opt_feat);
	uint8_t hdr[ZBC_MUTATE_RPT_HEADER_SIZE];
	uint8_t data[ZBC_MUTATE_RPT_RECORD_SIZE];

	if (len < ZBC_MUTATE_RPT_HEADER_SIZE) {
		tcmu_dev_warn(dev, "Allocated length %zu too small\n", len);
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_INVALID_FIELD_IN_CDB);
	}

	/* Set up report header */
	memset(hdr, 0, ZBC_MUTATE_RPT_HEADER_SIZE);
	zbc_cpbe32(&hdr[0], nr_recs);

	len = tcmu_memcpy_into_iovec(iovec, iov_cnt, hdr,
				     ZBC_MUTATE_RPT_HEADER_SIZE);
	if (len < ZBC_MUTATE_RPT_HEADER_SIZE)
		goto done;

	/* Output all supported device type/option combos */
	len = tcmu_iovec_length(iovec, iov_cnt);
	for (i = 0; i < nr_recs; i++, f++) {
		if (len < ZBC_MUTATE_RPT_RECORD_SIZE)
			break;

		memset(data, 0, ZBC_MUTATE_RPT_RECORD_SIZE);
		data[0] = f->type;
		zbc_cpbe32(&data[4], f->model.zd);

		tcmu_memcpy_into_iovec(iovec, iov_cnt, data,
				       ZBC_MUTATE_RPT_RECORD_SIZE);

		len -= ZBC_MUTATE_RPT_RECORD_SIZE;
	}

done:
	return TCMU_STS_OK;
}

/*
 * SCSI-specific REPORT MUTATIONS handler.
 */
static int zbc_scsi_report_mutations(struct tcmu_device *dev,
				     struct tcmulib_cmd *cmd)
{
	uint8_t *cdb = cmd->cdb;
	size_t len = tcmu_get_xfer_length(cdb);

	return zbc_report_mutations(dev, cmd, len);
}

/*
 * MUTATE: change device type between Legacy, ZBC and Zone Domains.
 */
static int zbc_mutate(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
		      enum zbc_device_type type, union zbc_mutation_opt model)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	struct zbc_dev_config *cfg = &zdev->cfg;
	const struct zbc_dev_features *feat;
	enum zbc_device_type prev_type;
	union zbc_mutation_opt prev_model;

	/* force_mutate mutates even if already the requested type */
	if (!zdev->force_mutate) {
		if (zdev->dev_type == type &&
		    zdev->dev_model.nz == model.nz) {
			tcmu_dev_dbg(dev,
				"MUTATE to the current type %u / model %u\n",
				type, model.zd);
			return TCMU_STS_OK;
		}
	}
	zdev->force_mutate = false;

	feat = zbc_get_dev_features(type, model);
	if (!feat) {
		tcmu_dev_warn(dev,
			      "MUTATE, unknown device type %u and model %u\n",
			      type, model.zd);
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_INVALID_FIELD_IN_CDB);
	}

	tcmu_dev_dbg(dev, "MUTATE, setting device type %u / model %u...\n",
		     type, model.zd);
	prev_type = zdev->dev_type;
	prev_model = zdev->dev_model;
	zdev->dev_type = type;
	zdev->dev_model = model;
	zbc_unmap_meta(zdev);

	cfg->mutating = true;
	if (zbc_format_meta(zdev)) {
		tcmu_dev_err(dev, "Can't format device, type/model %u/%u\n",
					type, model.zd);

		/*
		 * Try to go back to a good state --
		 * otherwise the device will not open to do a new mutation!
		 * The metadata is no longer mapped, the zone list has done
		 * re-init. (It actually opens but zbc_open() fails initial
		 * REPORT ZONES).
		 */
		tcmu_dev_err(dev, "Reverting to prior type/model %u/%u\n",
			prev_type, prev_model.zd);
		zdev->dev_type = prev_type;
		zdev->dev_model = prev_model;

		if (zbc_format_meta(zdev)) {
			tcmu_dev_err(dev,
			    "Can't revert to previous type/model %u/%u\n",
			    type, model.zd);
			/* One more try for sanity */
			zdev->dev_type = cfg->dev_type;
			zdev->dev_model = cfg->dev_model;
			cfg->zone_size = cfg->zone_size_cfgstr;
			cfg->realm_size = cfg->realm_size_cfgstr;
			cfg->smr_gain = cfg->smr_gain_cfgstr;
			zbc_format_meta(zdev);
		}

		cfg->mutating = false;
		return zbc_set_sense(cmd, HARDWARE_ERROR,
				     ASC_INTERNAL_TARGET_FAILURE);
	}
	cfg->mutating = false;

	if (!zbc_print_config(dev, zdev, true)) {
		/* bad zdev->dev_type */
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_INVALID_FIELD_IN_CDB);
	}

	return TCMU_STS_OK;
}

/*
 * SCSI-specific MUTATE handler.
 */
static int zbc_scsi_mutate(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	enum zbc_device_type type = cmd->cdb[2];
	union zbc_mutation_opt model;

	model = (union zbc_mutation_opt)zbc_rdbe32(&cmd->cdb[4]);

	return zbc_mutate(dev, cmd, type, model);
}

/*
 * Process SANITIZE command to re-format metadata. This feature
 * can be used to establish well-defined initial conditions before
 * running an automated test. The file contents currently is not
 * physically overwritten.
 *
 * The device doesn't change it's mutation after this operation.
 */
static int zbc_sanitize(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	struct zbc_dev_config *cfg = &zdev->cfg;
	uint8_t *cdb = cmd->cdb;

	/*
	 * Only do crypto sanitize since we are not erasing media.
	 * Also, since all write pointers will be reset, fail if ZNR
	 * bit is set in the CDB.
	 */
	if ((cdb[1] & 0x1f) != 0x03 || (cdb[1] & 0x40) != 0) {
		tcmu_dev_err(dev,
			     "Only Crypto SANITIZE, ZNR=0 is supported\n");
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_INVALID_FIELD_IN_CDB);
	}

	tcmu_dev_dbg(dev, "SANITIZE, resetting device...\n");
	zbc_unmap_meta(zdev);
	cfg->mutating = true;
	if (zbc_format_meta(zdev)) {
		tcmu_dev_err(dev, "Can't sanitize device\n");
		cfg->mutating = false;
		return zbc_set_sense(cmd, HARDWARE_ERROR,
				     ASC_INTERNAL_TARGET_FAILURE);
	}
	cfg->mutating = false;

	return TCMU_STS_OK;
}

/*
 * Process FORMAT command to re-format metadata.
 * Unlike during SANITIZE, the device mutation is reset to the
 * originalily configured value. Media is not physically erased.
 */
static int zbc_format(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);

	tcmu_dev_dbg(dev, "FORMAT, resetting device...\n");
	zbc_unmap_meta(zdev);
	zdev->dev_type = zdev->cfg.dev_type;
	if (zbc_format_meta(zdev))
		return zbc_set_sense(cmd, HARDWARE_ERROR,
				     ASC_INTERNAL_TARGET_FAILURE);

	return TCMU_STS_OK;
}

static int zbc_out_zone(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			uint64_t lba, unsigned int count, uint8_t op, bool all)
{
	struct zbc_dev *zdev;
	int ret = TCMU_STS_NOT_HANDLED;

	if (!all && !count)
		count++;

	switch (op) {
	case ZBC_SA_CLOSE_ZONE:
		ret = zbc_close_zone(dev, cmd, lba, count, all);
		break;
	case ZBC_SA_FINISH_ZONE:
		ret = zbc_finish_zone(dev, cmd, lba, count, all);
		break;
	case ZBC_SA_OPEN_ZONE:
		ret = zbc_open_zone(dev, cmd, lba, count, all);
		break;
	case ZBC_SA_RESET_WP:
		ret = zbc_reset_wp(dev, cmd, lba, count, all);
		break;
	case ZBC_SA_SEQUENTIALIZE_ZONE:
		ret = zbc_sequentialize_zone(dev, cmd, lba, count, all);
		break;
	default:
		zdev = tcmu_get_dev_private(dev);
		zdev->nr_nh_cmds++;
		break;
	}

	return ret;
}

/*
 * SCSI ZBC OUT: open zone, close zone, finish zone, reset wp,
 *               sequentialize and mutate command emulation.
 */
static int zbc_scsi_out(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	uint8_t *cdb = cmd->cdb;
	uint64_t lba;
	unsigned int count;
	uint8_t sa, all;

	sa = cdb[1] & 0x1f;
	all = cdb[14] & 0x01;
	lba = tcmu_get_lba(cdb);

	switch (sa) {
	case ZBC_SA_MUTATE:
		return zbc_scsi_mutate(dev, cmd);
	case ZBC_SA_CLOSE_ZONE:
	case ZBC_SA_FINISH_ZONE:
	case ZBC_SA_OPEN_ZONE:
	case ZBC_SA_RESET_WP:
	case ZBC_SA_SEQUENTIALIZE_ZONE:
		if (zbc_mt_zoned(zdev)) {
			count = zbc_rdbe16(&cdb[12]);
			return zbc_out_zone(dev, cmd, lba, count, sa, all);
		}
	}

	tcmu_dev_warn(dev, "Unsupported ZBC OUT SA 0x%02x\n", sa);

	return zbc_set_sense(cmd, ILLEGAL_REQUEST, ASC_INVALID_FIELD_IN_CDB);
}

static int zbc_request_sense(struct tcmu_device *dev,
			     struct tcmulib_cmd *cmd)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	uint8_t *cdb = cmd->cdb;
	struct iovec *iovec = cmd->iovec;
	size_t iov_cnt = cmd->iov_cnt;
	int i;
	uint8_t buf[18];

	if (cdb[1] & 0x01)
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_INVALID_FIELD_IN_CDB);

	memset(buf, 0, sizeof(buf));

	buf[0] = 0x70;
	buf[7] = 0xa;
	buf[2] = NO_SENSE;
	for (i = 0; i < ZBC_DEFERRED_SENSE_BUF_SIZE; i++) {
		if (zdev->def_sense[i]) {
			buf[2] = (zdev->def_sense[i] >> 16) & 0x0f;
			buf[12] = (zdev->def_sense[i] >> 8) & 0xff;
			buf[13] = zdev->def_sense[i] & 0xff;
			while (++i < ZBC_DEFERRED_SENSE_BUF_SIZE)
				zdev->def_sense[i - 1] = zdev->def_sense[i];
			zdev->def_sense[i - 1] = 0;
			break;
		}
	}

	tcmu_memcpy_into_iovec(iovec, iov_cnt, buf, sizeof(buf));

	return TCMU_STS_OK;
}

/*
 * READ CAPACITY(16) command emulation.
 */
static int zbc_read_capacity16(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	struct iovec *iovec = cmd->iovec;
	size_t iov_cnt = cmd->iov_cnt;
	uint8_t data[32];

	memset(data, 0, sizeof(data));

	if (zbc_mt_zd(zdev))
		/* Return the LBA of the last logical block in the CMR space */
		zbc_cpbe64(&data[0], zdev->logical_cmr_capacity - 1);
	else
		/* Return the LBA of the last logical block */
		zbc_cpbe64(&data[0], zdev->logical_capacity - 1);

	/* LBA size */
	zbc_cpbe32(&data[8], zdev->lba_size);

	if (zbc_mt_hm(zdev) || zbc_mt_ha(zdev))
		data[12] = 0x10; /* RC BASIS: maximum capacity */
	else
		data[12] = 0x00; /* RC BASIS: CMR space capacity */

	tcmu_memcpy_into_iovec(iovec, iov_cnt, data, sizeof(data));

	return TCMU_STS_OK;
}

/*
 * READ CAPACITY(10) command emulation. Only needed for non-zoned devices.
 */
static int zbc_read_capacity10(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	struct iovec *iovec = cmd->iovec;
	size_t iov_cnt = cmd->iov_cnt;
	uint8_t data[32];

	memset(data, 0, sizeof(data));

	if (!zbc_mt_nz(zdev)) {
		zdev->nr_nh_cmds++;
		return TCMU_STS_NOT_HANDLED;
	}

	if (zdev->logical_capacity >= (uint32_t)(-1)) {
		/* Indicate that the host needs to use RC(16) */
		zbc_cpbe32(&data[0], (uint32_t)(-1));
	} else {
		/* Return the LBA of the last logical block */
		zbc_cpbe32(&data[0], (uint32_t)(zdev->logical_capacity - 1));
	}

	/* LBA size */
	zbc_cpbe32(&data[4], zdev->lba_size);

	tcmu_memcpy_into_iovec(iovec, iov_cnt, data, sizeof(data));

	return TCMU_STS_OK;
}

/*
 * Turn unrestricted reads (URSWRZ) on or off.
 */
static void zbc_set_urswrz(struct zbc_dev *zdev, uint8_t urswrz)
{
	struct zbc_meta *meta = zdev->meta;

	if (urswrz == 0x00 || urswrz == 0x01) {
		if (zdev->wp_check && urswrz == 0x01) {
			tcmu_dev_dbg(zdev->dev, "Turning on URSWRZ\n");
			zdev->wp_check = false;
			meta->wp_check = 0x00;
		} else if (!zdev->wp_check && urswrz == 0x00) {
			tcmu_dev_dbg(zdev->dev, "Turning off URSWRZ\n");
			zdev->wp_check = true;
			meta->wp_check = 0x01;
		}
	}
}

/*
 * Set the number of subsequent zones to activate.
 */
static int zbc_set_subseq_nr_zones(struct zbc_dev *zdev, unsigned int fsnoz)
{
	struct zbc_meta *meta = zdev->meta;

	if (fsnoz && fsnoz != zdev->nr_actv_zones) {
		if (zdev->max_activate && fsnoz > zdev->max_activate) {
			tcmu_dev_warn(zdev->dev,
				"Subsequent # of zones %u too large, max %u\n",
				fsnoz, zdev->max_activate);
			return 1;
		}
		tcmu_dev_dbg(zdev->dev, "Setting FSNOZ to %u\n", fsnoz);
		zdev->nr_actv_zones = fsnoz;
		meta->nr_actv_zones = fsnoz;
	}

	return 0;
}

/*
 * Set MAXIMUM ACTIVATION value in zones.
 * This is a vendor-specific feature.
 */
static void zbc_set_max_activation(struct zbc_dev *zdev,
				   unsigned int max_activate)
{
	struct zbc_meta *meta = zdev->meta;

	if (max_activate != zdev->max_activate) {
		if (!max_activate || max_activate > zdev->nr_zones) {
			tcmu_dev_dbg(zdev->dev,
				     "Setting unlimited MAX ACTIVATION\n");
			zdev->max_activate = 0;
			meta->max_activate = 0;
		} else {
			tcmu_dev_dbg(zdev->dev,
				     "Setting MAX ACTIVATION %u realms\n",
				     max_activate);
			zdev->max_activate = max_activate;
			meta->max_activate = max_activate;
			if (zdev->nr_actv_zones > max_activate) {
				tcmu_dev_dbg(zdev->dev,
					     "Changing FSNOZ to %u\n",
					     max_activate);
				zdev->nr_actv_zones = max_activate;
				meta->nr_actv_zones = max_activate;
			}
		}
	}
}

static int zbc_ms_get_rwrecovery_page(struct tcmu_device *dev,
				      uint8_t *buf, size_t buf_len)
{
	if (buf_len) {
		if (buf_len < 12)
			return -1;

		buf[0] = 0x1;
		buf[1] = 0xa;
	}

	return 12;
}

static int zbc_ms_get_cache_page(struct tcmu_device *dev,
				 uint8_t *buf, size_t buf_len)
{
	if (buf_len) {
		if (buf_len < 20)
			return -1;

		buf[0] = 0x08;
		buf[1] = 0x12;
		buf[2] = 0x04; /* WCE=1 */
	}

	return 20;
}

static int zbc_ms_get_control_page(struct tcmu_device *dev,
				   uint8_t *buf, size_t buf_len)
{
	if (buf_len) {
		if (buf_len < 12)
			return -1;

		buf[0] = 0x0a;
		buf[1] = 0x0a;

		buf[2] = 0x02; /* GLTSD = 1 */
		buf[5] = 0x40; /* TAS = 1 */

		/* BUSY TIMEOUT PERIOD: unlimited */
		buf[8] = 0xff;
		buf[9] = 0xff;
	}

	return 12;
}

static int zbc_ms_get_zone_dom_page(struct tcmu_device *dev,
				    uint8_t *buf, size_t buf_len)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	const struct zbc_dev_features *feat = zdev->dev_feat;

	if (!buf_len)
		return 254;

	if (!zbc_mt_zd(zdev) || buf_len < 20)
		return -1;

	buf[0] = 0x3d | (0x3 << 6); /* Page, PS and SPF set */
	buf[1] = 0x08; /* Subpage */
	buf[3] = 254 - 3;

	if (!feat->no_za_control) {
		/* Output the current number of zones to activate (FSNOZ) */
		zbc_cpbe32(&buf[4], zdev->nr_actv_zones);
	}

	if (!feat->no_ur_control) {
		/*
		 * Output the current setting for URSWRZ.
		 * FIXME this layout is ad-hoc, TBD.
		 */
		buf[10] = zdev->wp_check ? 0x00 : 0x01;
	}


	if (feat->max_act_control) {
		/*
		 * MAXIMUM ACTIVATE zones.
		 * This is a vendor-specific field.
		 */
		zbc_cpbe16(&buf[16], zdev->max_activate);
	}

	return 254;
}

static int zbc_ms_set_zone_dom_page(struct tcmu_device *dev,
				    uint8_t *buf, size_t buf_len)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	const struct zbc_dev_features *feat = zdev->dev_feat;
	uint32_t fsnoz, max_activate;
	uint8_t urswrz;

	if (!zbc_mt_zd(zdev))
		return 1;

	fsnoz = zbc_rdbe32(&buf[4]);
	max_activate = zbc_rdbe16(&buf[16]);
	urswrz = buf[10];

	if (!feat->no_za_control) {
		if (zbc_set_subseq_nr_zones(zdev, fsnoz))
			return 1;
	} else if (fsnoz != 0) {
		return 1;
	}

	if (!feat->no_ur_control)
		zbc_set_urswrz(zdev, urswrz);
	else if (urswrz != 0x00)
		return 1;

	if (feat->max_act_control)
		zbc_set_max_activation(zdev, max_activate);
	else if (max_activate != 0)
		return 1;

	return 0;
}

/*
 * MODE SENSE / MODE SELECT handlers.
 */
struct zbc_mode_page {
	uint8_t	page;
	uint8_t	subpage;
	int	(*get)(struct tcmu_device *dev, uint8_t *buf, size_t buf_len);
	int	(*set)(struct tcmu_device *dev, uint8_t *buf, size_t buf_len);
};

static struct zbc_mode_page zbc_ms_handlers[] = {
	{0x01, 0,	zbc_ms_get_rwrecovery_page, NULL},
	{0x08, 0,	zbc_ms_get_cache_page, NULL},
	{0x0a, 0,	zbc_ms_get_control_page, NULL},
};

static struct zbc_mode_page zbc_ms_handlers_zd[] = {
	{0x01, 0,	zbc_ms_get_rwrecovery_page, NULL},
	{0x08, 0,	zbc_ms_get_cache_page, NULL},
	{0x0a, 0,	zbc_ms_get_control_page, NULL},
	/*
	 * FIXME the following mode page/subpage is
	 * in vendor-specific range, the final value TBD
	 */
	{0x3d, 0x08,	zbc_ms_get_zone_dom_page, zbc_ms_set_zone_dom_page},
};

static int zbc_handle_mode_page(struct tcmu_device *dev, uint8_t *buf,
				size_t buf_len, int pg, int subpg, bool set)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	struct zbc_mode_page *mph;
	int i, size, len = 0, ret = -1;

	if (zbc_mt_zd(zdev)) {
		mph = zbc_ms_handlers_zd;
		size = ARRAY_SIZE(zbc_ms_handlers_zd);
	} else {
		mph = zbc_ms_handlers;
		size = ARRAY_SIZE(zbc_ms_handlers);
	}

	for (i = 0; i < size; i++) {
		if ((pg < 0 || pg == mph[i].page) &&
		    (subpg < 0 || subpg == mph[i].subpage)) {
			if (!set && mph[i].get) {
				ret = mph[i].get(dev, &buf[len],
						 buf_len - len);
				if (ret <= 0)
					break;
				len += ret;
			} else if (set && mph[i].set) {
				ret = mph[i].set(dev, &buf[len],
						 buf_len - len);
				break;
			}
		}
	}

	return set ? ret : len;
}

/*
 * Mode sense command emulation.
 */
static int zbc_mode_sense(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct iovec *iovec = cmd->iovec;
	size_t iov_cnt = cmd->iov_cnt;
	uint8_t *cdb = cmd->cdb;
	uint8_t page_code = cdb[2] & 0x3f;
	uint8_t subpage_code = cdb[3];
	size_t alloc_len, len;
	int ret;
	uint8_t data[512];
	bool sense_ten = (cdb[0] == MODE_SENSE_10);

	memset(data, 0, sizeof(data));

	/* Mode parameter header. Mode data length filled in at the end. */
	alloc_len = tcmu_get_xfer_length(cdb);
	len = sense_ten ? 8 : 4;

	if (page_code == 0x3f)
		ret = zbc_handle_mode_page(dev, data + len, alloc_len - len,
					   -1, -1, false);
	else
		ret = zbc_handle_mode_page(dev, data + len, alloc_len - len,
					   page_code, subpage_code, false);

	if (ret <= 0) {
		tcmu_dev_dbg(dev,
			     "MODE SENSE(%s) err %i, page 0x%x/0x%x\n",
			     sense_ten ? "10" : "6", ret,
			     page_code, subpage_code);
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_INVALID_FIELD_IN_CDB);
	}

	len += ret;

	if (sense_ten)
		zbc_cpbe16(&data[0], len - 2);
	else
		data[0] = len - 1;

	tcmu_memcpy_into_iovec(iovec, iov_cnt, data, sizeof(data));

	return TCMU_STS_OK;
}

/*
 * Mode select command emulation.
 */
static int zbc_mode_select(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct iovec *iovec = cmd->iovec;
	size_t iov_cnt = cmd->iov_cnt;
	uint8_t *cdb = cmd->cdb;
	uint8_t page_code, subpage_code;
	uint8_t in_buf[512], buf[512];
	size_t alloc_len, len;
	int ret;
	bool select_ten = (cdb[0] == MODE_SELECT_10);

	/* Abort if !pf or sp */
	if (!(cdb[1] & 0x10) || (cdb[1] & 0x01))
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_INVALID_FIELD_IN_CDB);

	memset(in_buf, 0, sizeof(in_buf));

	alloc_len = tcmu_get_xfer_length(cdb);
	if (!alloc_len)
		return TCMU_STS_OK;

	len = tcmu_memcpy_from_iovec(in_buf, sizeof(in_buf), iovec, iov_cnt);
	if (len >= sizeof(in_buf)) {
		tcmu_dev_dbg(dev, "MODE SELECT buffer is too long, %zu bytes\n",
			     len);
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_PARAMETER_LIST_LENGTH_ERROR);
	}
	len = select_ten ? 8 : 4;
	page_code = in_buf[len] & 0x3f;
	subpage_code = (in_buf[len] & 0x40) ? in_buf[len + 1] : 0;

	ret = zbc_handle_mode_page(dev, in_buf + len, alloc_len - len,
				   page_code, subpage_code, true);

	if (ret > 0) {
		tcmu_dev_dbg(dev, "MODE SELECT(%s) err %i, page 0x%x/0x%x\n",
			     select_ten ? "10" : "6", ret,
			     page_code, subpage_code);
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_INVALID_FIELD_IN_CDB);
	} else if (ret < 0) {
		/* No MODE SELECT handler defined */
		ret = zbc_handle_mode_page(dev, buf, alloc_len,
					   page_code, subpage_code, false);

		if (ret <= 0 || memcmp(buf, &in_buf[len], ret)) {
			tcmu_dev_dbg(dev, "MODE SELECT buffer mismatch\n");
			return zbc_set_sense(cmd, ILLEGAL_REQUEST,
					ASC_INVALID_FIELD_IN_PARAMETER_LIST);
		}
	}

	return TCMU_STS_OK;
}

/*
 * Check the given LBA range.
 */
static int zbc_check_rdwr(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			  uint64_t lba, size_t nr_lbas)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	size_t iov_length = tcmu_iovec_length(cmd->iovec, cmd->iov_cnt);

	if (zbc_lba_out_of_range(zdev, cmd, lba, nr_lbas)) {
		tcmu_dev_warn(dev, "Cmd past high LBA %llu (lba %"PRIu64
				   ", xfer len %zu)\n",
			      zdev->logical_capacity - 1, lba, nr_lbas);
		return zbc_set_sense(cmd, ILLEGAL_REQUEST,
				     ASC_LBA_OUT_OF_RANGE);
	}

	if (iov_length != nr_lbas << zdev->lba_log2) {
		tcmu_dev_err(dev,
			"iov mismatch: len %zu, xfr len %zu, block size %zu\n",
			iov_length, nr_lbas, zdev->lba_size);
		return zbc_set_sense(cmd, HARDWARE_ERROR,
				     ASC_INTERNAL_TARGET_FAILURE);
	}

	return TCMU_STS_OK;
}

/*
 * Get the backstore file offset of an LBA.
 */
static inline uint64_t zbc_bs_offset(struct zbc_dev *zdev, uint64_t lba)
{
	if (zbc_mt_zd(zdev)) {
		/*
		 * FIXME this process is getting too expensive to perform
		 * it for every I/O block. Need to find the domain once and
		 * then subtract it's start LBA for every block.
		 * Unrolling the loop for now.
		 */
		if (lba <= zdev->domains[0].end_lba)
			;
		else if (lba <= zdev->domains[1].end_lba)
			lba -= zdev->domains[1].start_lba;
		else if (lba <= zdev->domains[2].end_lba)
			lba -= zdev->domains[2].start_lba;
		else if (lba <= zdev->domains[3].end_lba)
			lba -= zdev->domains[3].start_lba;
	}

	return zdev->meta_size + (lba << zdev->lba_log2);
}

/*
 * Get the number of LBAs left to transfer for a zone.
 */
static inline size_t zbc_get_zone_lba_count(struct zbc_zone *zone,
					    uint64_t start_lba, size_t nr_lbas)
{
	if (start_lba + nr_lbas > zone->start + zone->len)
		return zone->start + zone->len - start_lba;
	else
		return nr_lbas;
}

/*
 * Get the upper boundary of valid data in a zone.
 */
static inline uint64_t zbc_get_zone_boundary(struct zbc_zone *zone)
{
	if (zbc_zone_empty(zone) || zbc_zone_gap(zone))
		return zone->start;
	else if (zbc_zone_not_wp(zone) || zbc_zone_full(zone))
		return zone->start + zone->len;
	else
		return zone->wp;
}

/*
 * Read zero data for a zone starting from "lba".
 * Called for reads above the write pointer.
 */
static ssize_t zbc_fill_zone_iov(struct zbc_dev *zdev, struct zbc_zone *zone,
				 uint64_t lba, size_t nr_lbas,
				 struct iovec *iov, size_t iov_cnt)
{
	size_t len, to_fill;
	ssize_t bytes = 0;

	len = zone->start + zone->len - lba;
	if (len > nr_lbas)
		len = nr_lbas;
	len = len << zdev->lba_log2;

	tcmu_dev_dbg(zdev->dev, "Read %zu zeroes at LBA %"PRIu64
				", type %u, cond %u, WP %llu\n",
		     len, lba, zone->type, zone->cond, zone->wp);

	for (; len && iov_cnt; iov++, iov_cnt--) {
		to_fill = min(iov->iov_len, len);

		if (to_fill) {
			memset(iov->iov_base, 0, to_fill);
			iov->iov_base += to_fill;
			iov->iov_len -= to_fill;
			len -= to_fill;
			bytes += to_fill;
		}
	}

	return bytes;
}

/*
 * Read data from a zone starting from "lba" and up the the upper
 * boundary of valid data.
 */
static ssize_t zbc_read_zone_iov(struct zbc_dev *zdev, struct zbc_zone *zone,
				 uint64_t lba, size_t nr_lbas, size_t boundary,
				 struct iovec *iov, size_t iov_cnt)
{
	size_t len, to_read, ret;
	ssize_t bytes = 0;

	len = boundary - lba;
	if (len > nr_lbas)
		len = nr_lbas;
	len = len << zdev->lba_log2;

	tcmu_dev_dbg(zdev->dev, "Read %zu bytes at LBA %"PRIu64"\n", len, lba);

	for (; len && iov_cnt; iov++, iov_cnt--) {
		to_read = min(iov->iov_len, len);

		if (to_read) {
			ret = pread(zdev->fd, iov->iov_base, to_read,
				    zbc_bs_offset(zdev, lba));
			if (ret != to_read) {
				tcmu_dev_err(zdev->dev,
					     "Read failed %zd / %zu B\n",
					     ret, bytes);
				return -EIO;
			}

			lba += ret >> zdev->lba_log2;
			iov->iov_base += to_read;
			iov->iov_len -= to_read;
			len -= to_read;
			bytes += to_read;
		}
	}

	return bytes;
}

/*
 * Write data to a zone starting from "lba".
 */
static ssize_t zbc_write_zone_iov(struct zbc_dev *zdev, struct zbc_zone *zone,
				  uint64_t lba, size_t nr_lbas,
				  struct iovec *iov, size_t iov_cnt)
{
	size_t len, to_write, ret;
	ssize_t bytes = 0;

	len = zbc_get_zone_lba_count(zone, lba, nr_lbas);
	len = len << zdev->lba_log2;

	tcmu_dev_dbg(zdev->dev, "Write %zu bytes at LBA %"PRIu64"\n",
		     len, lba);

	for (; len && iov_cnt; iov++, iov_cnt--) {
		to_write = min(iov->iov_len, len);

		if (to_write) {
			ret = pwrite(zdev->fd, iov->iov_base, to_write,
				     zbc_bs_offset(zdev, lba));
			if (ret != to_write) {
				tcmu_dev_err(zdev->dev,
					     "Write failed %zd / %zu B\n",
					     ret, bytes);
				return -EIO;
			}

			lba += ret >> zdev->lba_log2;
			iov->iov_base += to_write;
			iov->iov_len -= to_write;
			len -= to_write;
			bytes += to_write;
		}
	}

	return bytes;
}

/*
 * Check if the given zone satisfies all protocol conditions for read.
 */
static bool zbc_zone_ok_to_read(struct tcmu_device *dev,
				struct zbc_zone *zone, uint64_t lba,
				size_t nr_lbas, unsigned int first_zn_type,
				unsigned int first_zn_cond,
				uint8_t *psk, uint16_t *pasc)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	uint64_t boundary;

	/* Gap zones can be read as a fill pattern if URSWRZ = 1 */
	if (zbc_zone_gap(zone) && zdev->wp_check) {
		tcmu_dev_warn(dev,
			      "Reading GAP zone, URSWRZ 0, LBA %"PRIu64"\n",
			      lba);
		*psk = ILLEGAL_REQUEST;
		*pasc = ASC_ATTEMPT_TO_ACCESS_GAP_ZONE;
		return false;
	}

	/* Check for any read zones in offline condition */
	if (zbc_zone_offline(zone)) {
		tcmu_dev_warn(dev, "Read an offline zone, LBA %"PRIu64"\n",
			      lba);
		*psk = DATA_PROTECT;
		*pasc = ASC_ZONE_IS_OFFLINE;
		return false;
	}

	/*
	 * Inactive zones can be read as a fill pattern if URSWRZ = 1.
	 * SWP inactive zones, however, can be read regardless of SWP.
	 * Conventional inactive zones act the same even though their
	 * behavior is not defined by specifications.
	 */
	if (zbc_zone_inactive(zone) && zdev->wp_check &&
	    !zbc_zone_conv(zone) && !zbc_zone_seq_pref(zone)) {
		tcmu_dev_warn(dev,
			      "Read inactive zone, URSWRZ 0, LBA %"PRIu64"\n",
			      lba);
		*psk = DATA_PROTECT;
		*pasc = ASC_ZONE_IS_INACTIVE;
		return false;
	}

	/* Check for crossing any zone-type boundary */
	if (zone->type != first_zn_type) {
		tcmu_dev_warn(dev,
			"Read boundary violation LBA %"PRIu64", xfer len %zu\n",
			lba, nr_lbas);
		*psk = ILLEGAL_REQUEST;
		*pasc = ASC_READ_BOUNDARY_VIOLATION;
		return false;
	}

	/* No read restrictions when URSWRZ enabled */
	if (!zdev->wp_check)
		return true;

	/* No Read restrictions on CONV/SWP zones */
	if (zbc_zone_conv(zone) || zbc_zone_seq_pref(zone))
		return true;

	/* Enforce read restrictions on SWR/SOBR zones */

	/* Check for crossing SWR zone boundary */
	if (zbc_zone_seq_req(zone) &&
	    lba + nr_lbas > zone->start + zone->len) {
		tcmu_dev_warn(dev,
			"Read boundary violation LBA %"PRIu64", xfr len %zu\n",
			lba, nr_lbas);
		*psk = ILLEGAL_REQUEST,
		*pasc = ASC_READ_BOUNDARY_VIOLATION;
		return false;
	}

	/* Check SWR/SOBR write-pointer restrictions on read operations */

	/* Get valid data boundary for this zone */
	boundary = zbc_get_zone_boundary(zone);

	if (lba < boundary &&
		zbc_get_zone_lba_count(zone, lba, nr_lbas) >
						boundary - lba) {
		tcmu_dev_warn(dev,
			"Read thru WP LBA %"PRIu64", xfr len %zu\n",
			lba, nr_lbas);
		*psk = ILLEGAL_REQUEST;
		*pasc = ASC_ATTEMPT_TO_READ_INVALID_DATA;
		return false;

	} else if (lba >= boundary) {
		tcmu_dev_warn(dev,
			"Read over WP LBA %"PRIu64", xfr len %zu\n",
			lba, nr_lbas);
		*psk = ILLEGAL_REQUEST;
		*pasc = ASC_ATTEMPT_TO_READ_INVALID_DATA;
		return false;
	}

	return true;
}

/*
 * Check if the given zone satisfies all protocol conditions for write.
 */
static bool zbc_zone_ok_to_write(struct tcmu_device *dev,
				 struct zbc_zone *zone, uint64_t lba,
				 size_t nr_lbas, unsigned int first_zn_type,
				 unsigned int first_zn_cond,
				 uint8_t *psk, uint16_t *pasc)
{
	/*
	 * Check for boundary starting or crossing into
	 * gap, offline, inactive or read-only zones.
	 */
	if (zbc_zone_gap(zone)) {
		tcmu_dev_warn(dev, "Write LBA %"PRIu64
				   " is a GAP zone, first %u\n",
			      lba, first_zn_type);
		*psk = ILLEGAL_REQUEST;
		*pasc = ASC_ATTEMPT_TO_ACCESS_GAP_ZONE;
		return false;
	}
	if (zbc_zone_offline(zone)) {
		tcmu_dev_warn(dev, "Write LBA %"PRIu64
				    " is an OFFLINE zone, first %u\n",
			      lba, first_zn_type);
		*psk = DATA_PROTECT;
		*pasc = ASC_ZONE_IS_OFFLINE;
		return false;
	}
	if (zbc_zone_inactive(zone)) {
		tcmu_dev_warn(dev, "Write LBA %"PRIu64
				   " is an INACTIVE zone, first %u\n",
			      lba, first_zn_type);
		*psk = DATA_PROTECT;
		*pasc = ASC_ZONE_IS_INACTIVE;
		return false;
	}
	if (zbc_zone_rdonly(zone)) {
		tcmu_dev_warn(dev, "Write LBA %"PRIu64
				   " is a READONLY zone, first %u\n",
			      lba, first_zn_type);
		*psk = DATA_PROTECT;
		*pasc = ASC_ZONE_IS_READ_ONLY;
		return false;
	}

	/* Check conv -> seq and seq -> seq zone boundary crossing */
	if (zone->type != first_zn_type ||
	    (zbc_zone_seq_req(zone) &&
	     lba + nr_lbas > zone->start + zone->len)) {
		tcmu_dev_warn(dev, "Write boundary violation: LBA %"PRIu64
				   ", xfr len %zu\n",
			      lba, nr_lbas);
		*psk = ILLEGAL_REQUEST,
		*pasc = ASC_WRITE_BOUNDARY_VIOLATION;
		return false;
	}

	/* Check for an attempt to write to a full SWR zone */
	if (zbc_zone_seq_req(zone) && zbc_zone_full(zone)) {
		tcmu_dev_warn(dev,
			"Write to FULL zone: start %llu, LBA %"PRIu64"\n",
			zone->start, lba);
		*psk = ILLEGAL_REQUEST;
		*pasc = ASC_INVALID_FIELD_IN_CDB;
		return false;
	}

	/*
	 * For sequential write required zones,
	 * enforce the write pointer position.
	 */
	if (zbc_zone_seq_req(zone) && lba != zone->wp) {
		tcmu_dev_warn(dev,
			      "Unaligned write LBA %"PRIu64
			      ", wp %llu, cond %u\n",
			      lba, zone->wp, zone->cond);
		*psk = ILLEGAL_REQUEST;
		*pasc = ASC_UNALIGNED_WRITE_COMMAND;
		return false;
	}

	/*
	 * In SOBR zones, it is possible to write below the write pointer
	 * position, but not above. If the zone is full, there is no WP.
	 */
	if (zbc_zone_sobr(zone) && !zbc_zone_full(zone) && lba > zone->wp) {
		tcmu_dev_warn(dev,
			      "Unaligned write LBA %"PRIu64
			      ", wp %llu, cond %u\n",
			      lba, zone->wp, zone->cond);
		*psk = ILLEGAL_REQUEST;
		*pasc = ASC_UNALIGNED_WRITE_COMMAND;
		return false;
	}

	return true;
}

static void zbc_adjust_write_ptr(struct zbc_dev *zdev, struct zbc_zone *zone,
				 uint64_t lba, size_t count)
{
	if (zbc_zone_seq_req(zone)) {
		zone->wp += count;
	} else if (zbc_zone_seq_pref(zone) || zbc_zone_sobr(zone)) {
		if (lba + count > zone->wp)
			zone->wp = lba + count;
	}
	if (zone->wp >= zone->start + zone->len) {
		if (zbc_zone_is_open(zone))
			__zbc_close_zone(zdev, zone);
		if (zbc_zone_conv(zone)) {
			zone->cond = ZBC_ZONE_COND_NOT_WP;
			zone->wp = ZBC_NO_WP;
		} else {
			zbc_unlink_zone(zdev, zone);
			zbc_on_cond_change(zdev, zone, ZBC_ZONE_COND_FULL);
			zone->cond = ZBC_ZONE_COND_FULL;
			if (zbc_zone_seq(zone))
				zone->wp = zone->start + zone->len;
			else
				zone->wp = ZBC_NO_WP;
			zbc_add_zone_tail(zdev, zdev->seq_active_zones, zone);
		}
	}
}

/*
 * Check zone boundary crossings, INACTIVE, etc...
 */
static int zbc_rdwr_check_zones(struct tcmu_device *dev,
				struct tcmulib_cmd *cmd, bool read,
				uint64_t lba, size_t nr_lbas)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	struct zbc_zone *zone;
	size_t count;
	unsigned int first_zn_type = 0, first_zn_cond;
	uint16_t asc;
	uint8_t sk;

	do {
		/* Get the zone of the first LBA */
		zone = zbc_get_zone(zdev, lba, false);
		if (!zone)
			return zbc_set_sense(cmd, HARDWARE_ERROR,
					     ASC_INTERNAL_TARGET_FAILURE);

		if (first_zn_type == 0) {
			first_zn_type = zone->type;
			first_zn_cond = zone->cond;
		}

		if (read) {
			/* Perform read zone checks */
			if (!zbc_zone_ok_to_read(dev, zone, lba, nr_lbas,
						 first_zn_type, first_zn_cond,
						 &sk, &asc)) {
				zdev->read_rule_fails++;
				return zbc_set_sense(cmd, sk, asc);
			}
		} else {
			/* Perform write zone checks */
			if (!zbc_zone_ok_to_write(dev, zone, lba, nr_lbas,
						  first_zn_type, first_zn_cond,
						  &sk, &asc)) {
				zdev->write_rule_fails++;
				return zbc_set_sense(cmd, sk, asc);
			}
		}

		count = zbc_get_zone_lba_count(zone, lba, nr_lbas);
		lba += count;
		nr_lbas -= count;
	} while (nr_lbas > 0);

	return TCMU_STS_OK;
}

/*
 * Zoned read command emulation.
 *
 * As we read data, check that we do not cross a
 * conventional to sequential zone boundary.
 */
static int zbc_read_zoned(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			  uint64_t lba, size_t len)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	struct zbc_zone *zone;
	size_t count, boundary;
	ssize_t ret;

	tcmu_dev_dbg(dev, "Read LBA %"PRIu64"+%zu, %zu vectors\n",
		     lba, len, cmd->iov_cnt);

	/* Check LBA and length */
	ret = zbc_check_rdwr(dev, cmd, lba, len);
	if (ret != TCMU_STS_OK)
		return ret;

	/* Check read alignment and zones */
	ret = zbc_rdwr_check_zones(dev, cmd, true, lba, len);
	if (ret != TCMU_STS_OK)
		return ret;

	/* Do read */
	while (len) {
		/* Get the zone of the current LBA */
		zone = zbc_get_zone(zdev, lba, false);
		if (!zone)
			return zbc_set_sense(cmd, HARDWARE_ERROR,
					     ASC_INTERNAL_TARGET_FAILURE);

		/* Get the upper boundary of valid data */
		boundary = zbc_get_zone_boundary(zone);
		if (lba >= boundary)
			/* Output zeroes for read after WP */
			ret = zbc_fill_zone_iov(zdev, zone, lba,
						len, cmd->iovec,
						cmd->iov_cnt);
		else
			/* Read previously written data */
			ret = zbc_read_zone_iov(zdev, zone, lba,
						len, boundary,
						cmd->iovec, cmd->iov_cnt);

		if (ret <= 0) {
			tcmu_dev_err(dev, "Read failed: %m\n");
			return zbc_set_sense(cmd, MEDIUM_ERROR,
					     ASC_READ_ERROR);
		}

		count = ret >> zdev->lba_log2;

		lba += count;
		len -= count;
	}

	return TCMU_STS_OK;
}

/*
 * Zoned device write command emulation.
 */
static int zbc_write_zoned(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			   uint64_t lba, size_t len)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	struct zbc_zone *zone;
	size_t count;
	ssize_t ret;

	tcmu_dev_dbg(dev, "Write LBA %"PRIu64"+%zu, %zu vectors\n",
		     lba, len, cmd->iov_cnt);

	/* Check LBA and length */
	ret = zbc_check_rdwr(dev, cmd, lba, len);
	if (ret != TCMU_STS_OK)
		return ret;

	/* Check write alignment and zones */
	ret = zbc_rdwr_check_zones(dev, cmd, false, lba, len);
	if (ret != TCMU_STS_OK)
		return ret;

	/* Do write */
	do {
		/* Get the zone of the current LBA */
		zone = zbc_get_zone(zdev, lba, false);
		if (!zone)
			return zbc_set_sense(cmd, HARDWARE_ERROR,
					     ASC_INTERNAL_TARGET_FAILURE);

		/* If the zone is not open, implicitly open it */
		if ((zbc_zone_seq(zone) || zbc_zone_sobr(zone)) &&
		    !zbc_zone_is_open(zone) && !zbc_zone_full(zone)) {

			if (zbc_zone_seq_req(zone) &&
			    !zbc_ozr_check(zdev, 1)) {
				return zbc_set_sense(cmd, DATA_PROTECT,
					ASC_INSUFFICIENT_ZONE_RESOURCES);
			}
			__zbc_open_zone(zdev, zone, false);
		}

		if (len == 0)
			break;

		ret = zbc_write_zone_iov(zdev, zone, lba, len,
					 cmd->iovec, cmd->iov_cnt);
		if (ret <= 0) {
			tcmu_dev_err(dev, "Write failed: %m\n");
			return zbc_set_sense(cmd, MEDIUM_ERROR,
					     ASC_WRITE_ERROR);
		}

		count = ret >> zdev->lba_log2;

		/* Adjust write pointer in this zone */
		zbc_adjust_write_ptr(zdev, zone, lba, count);

		lba += count;
		len -= count;

	} while (len);

	return TCMU_STS_OK;
}

/*
 * Non-zoned read command emulation.
 */
static int zbc_read_nz(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
		       uint64_t lba, size_t len)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	ssize_t ofs, ret;

	tcmu_dev_dbg(dev, "Read LBA %"PRIu64"+%zu, %zu vectors\n",
		     lba, len, cmd->iov_cnt);

	/* Check LBA and length */
	ret = zbc_check_rdwr(dev, cmd, lba, len);
	if (ret != TCMU_STS_OK)
		return ret;

	ofs = zbc_bs_offset(zdev, lba);
	len = len << zdev->lba_log2;
	ret = preadv(zdev->fd, cmd->iovec, cmd->iov_cnt, ofs);
	if (ret != len) {
		tcmu_dev_err(dev, "Read failed %zd / %zu B\n", ret, len);
		return zbc_set_sense(cmd, MEDIUM_ERROR,
				     ASC_READ_ERROR);
	}

	return TCMU_STS_OK;
}

/*
 * Non-zoned device write command emulation.
 */
static int zbc_write_nz(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			uint64_t lba, size_t len)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	ssize_t ofs, ret;

	tcmu_dev_dbg(dev, "Write LBA %"PRIu64"+%zu, %zu vectors\n",
		     lba, len, cmd->iov_cnt);

	/* Check LBA and length */
	ret = zbc_check_rdwr(dev, cmd, lba, len);
	if (ret != TCMU_STS_OK)
		return ret;

	/* Do write */
	ofs = zbc_bs_offset(zdev, lba);
	len = len << zdev->lba_log2;
	ret = pwritev(zdev->fd, cmd->iovec, cmd->iov_cnt, ofs);
	if (ret != len) {
		tcmu_dev_err(dev, "Write failed %zd / %zu B\n", ret, len);
		return zbc_set_sense(cmd, MEDIUM_ERROR,
				     ASC_WRITE_ERROR);
	}

	return TCMU_STS_OK;
}

/*
 * Read command emulation.
 */
static inline int zbc_read(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			   uint64_t lba, size_t len)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);

	if (!zbc_mt_nz(zdev))
		return zbc_read_zoned(dev, cmd, lba, len);
	else
		return zbc_read_nz(dev, cmd, lba, len);
}

/*
 * Process SCSI read CDB and call the protocol-independent read handler.
 */
static inline int zbc_scsi_read(struct tcmu_device *dev,
				struct tcmulib_cmd *cmd)
{
	uint64_t lba = tcmu_get_lba(cmd->cdb);
	size_t len = tcmu_get_xfer_length(cmd->cdb);

	return zbc_read(dev, cmd, lba, len);
}

static void zbc_fill_stat_log_param(struct zbc_dev *zdev,
				    uint8_t *data, int code)
{
	uint64_t val;

	switch (code) {
	case 0x00:
		val = zdev->max_open_zones; break;
	case 0x01:
		val = zdev->max_exp_open_seq_zones; break;
	case 0x02:
		val = zdev->max_imp_open_seq_zones; break;
	case 0x03:
		val = zdev->min_empty_zones; break;
	case 0x04:
		val = zdev->max_non_seq_zones; break;
	case 0x05:
		val = zdev->zones_emptied; break;
	case 0x06:
		val = zdev->subopt_write_cmds; break;
	case 0x07:
		val = zdev->cmds_above_opt_lim; break;
	case 0x08:
		val = zdev->failed_exp_opens; break;
	case 0x09:
		val = zdev->read_rule_fails; break;
	case 0x0a:
		val = zdev->write_rule_fails; break;
	case 0x0b:
		val = zdev->max_imp_open_sobr_zones; break;
	default:
		tcmu_dev_err(zdev->dev, "Bad log param code %i\n", code);
		return;
	}

	zbc_cpbe16(data, code); /* Parameter code */
	data[2] = 0x03; /* Binary format */
	data[3] = 8; /* Length */
	zbc_cpbe64(&data[4], val); /* Value */
}

/*
 * RECEIVE DIAGNOSTIC RESULTS command handler.
 */
static int zbc_scsi_receive_diag(struct tcmu_device *dev,
				 struct tcmulib_cmd *cmd)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	uint8_t *cdb = cmd->cdb;
	struct iovec *iovec = cmd->iovec;
	size_t iov_cnt = cmd->iov_cnt, len;
	int i, page = cdb[2], size;
	uint8_t data[ZBC_LOG_PARAM_RECORD_SIZE];

	if (cdb[1] & 0x01) { /* PCV bit */
		if (page != ZBC_ZBD_LOG_SUPP_PAGES &&
		    page != ZBC_ZBD_LOG_STATS) {
			tcmu_dev_warn(dev,
				      "Unsupported diagnostic page 0x%02x\n",
				      page);
			return zbc_set_sense(cmd, ILLEGAL_REQUEST,
					     ASC_INVALID_FIELD_IN_CDB);
		}
	} else {
		page = ZBC_ZBD_LOG_SUPP_PAGES;
	}

	/*
	 * FIXME tcmu_get_xfer_length() doesn't correctly read
	 * the transfer length for this opcode...
	 */
	len = zbc_rdbe16(&cdb[3]);

	memset(data, 0, sizeof(data));
	switch (page) {
	case ZBC_ZBD_LOG_SUPP_PAGES:
		if (len < 6)
			goto no_room;
		data[0] = ZBC_ZBD_LOG_SUPP_PAGES;
		zbc_cpbe16(&data[2], 2);
		data[4] = ZBC_ZBD_LOG_SUPP_PAGES;
		data[5] = ZBC_ZBD_LOG_STATS;
		tcmu_memcpy_into_iovec(iovec, iov_cnt, data, 6);

		break;

	case ZBC_ZBD_LOG_STATS:
		size = ZBC_LOG_PARAM_RECORD_SIZE * ZBC_NR_STAT_PARAMS + 4;
		if (len < size)
			goto no_room;
		data[0] = ZBC_ZBD_LOG_STATS;
		data[0] |= 0x40; /* SPF */
		data[1] = 0x01; /* Subpage */
		zbc_cpbe16(&data[2], size - 4); /* Page length */
		size = tcmu_memcpy_into_iovec(iovec, iov_cnt, data, 4);
		if (size != 4)
			goto no_room;
		for (i = 0; i < ZBC_NR_STAT_PARAMS; i++) {
			zbc_fill_stat_log_param(zdev, data, i);
			size = tcmu_memcpy_into_iovec(iovec, iov_cnt, data,
						ZBC_LOG_PARAM_RECORD_SIZE);
			if (size != ZBC_LOG_PARAM_RECORD_SIZE)
				goto no_room;
		}
		break;

	default:
		zdev->nr_nh_cmds++;
		return TCMU_STS_NOT_HANDLED;
	}

	return TCMU_STS_OK;

no_room:
	tcmu_dev_warn(dev,
		      "Diag page 0x%02x - transfer length %zu too small\n",
		      page, len);
	return zbc_set_sense(cmd, ILLEGAL_REQUEST,
			     ASC_INVALID_FIELD_IN_PARAMETER_LIST);
}

/*
 * Write command emulation.
 */
static inline int zbc_write(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			    uint64_t lba, size_t len)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);

	if (!zbc_mt_nz(zdev))
		return zbc_write_zoned(dev, cmd, lba, len);
	else
		return zbc_write_nz(dev, cmd, lba, len);
}

/*
 * Process SCSI write CDB and call the protocol-independent write handler.
 */
static inline int zbc_scsi_write(struct tcmu_device *dev,
				 struct tcmulib_cmd *cmd)
{
	uint64_t lba = tcmu_get_lba(cmd->cdb);
	size_t len = tcmu_get_xfer_length(cmd->cdb);

	return zbc_write(dev, cmd, lba, len);
}

/*
 * Synchronize cache command emulation.
 */
static int zbc_flush(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	int ret;

	ret = fsync(zdev->fd);
	if (ret == 0)
		ret = zbc_flush_meta(zdev);
	if (ret) {
		tcmu_dev_err(dev, "flush failed\n");
		return zbc_set_sense(cmd, MEDIUM_ERROR, ASC_WRITE_ERROR);
	}

	return TCMU_STS_OK;
}

/*
 * SCSI ZBC IN: report zones, domains, realms, zone activate/query
 *              and report mutations command emulation.
 */
static int zbc_scsi_in(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	const struct zbc_dev_features *feat = zdev->dev_feat;
	uint8_t *cdb = cmd->cdb;
	uint8_t op = cdb[1] & 0x1f;

	switch (op) {
	case ZBC_SA_REPORT_ZONES:
		if (!zbc_mt_nz(zdev))
			return zbc_scsi_report_zones(dev, cmd);
		break;

	case ZBC_SA_REPORT_ZONE_DOMAINS:
		if (zbc_mt_zd(zdev))
			return zbc_scsi_report_zone_domains(dev, cmd);
		break;

	case ZBC_SA_REPORT_REALMS:
		if (zbc_mt_zd(zdev) &&
		    zdev->realms_feat_set && !feat->no_report_realms)
			return zbc_scsi_report_realms(dev, cmd);
		break;

	case ZBC_SA_ZONE_ACTIVATE_16:
		if (zbc_mt_zd(zdev))
			return zbc_scsi_zone_activate16(dev, cmd, false);
		break;

	case ZBC_SA_ZONE_QUERY_16:
		if (zbc_mt_zd(zdev))
			return zbc_scsi_zone_activate16(dev, cmd, true);
		break;

	case ZBC_SA_REPORT_MUTATIONS:
		return zbc_scsi_report_mutations(dev, cmd);
	}

	tcmu_dev_warn(dev, "Unsupported SCSI ZBC IN action 0x%X\n", op);
	return zbc_set_sense(cmd, ILLEGAL_REQUEST,
			     ASC_INVALID_FIELD_IN_CDB);
}

/*
 * Handle command emulation.
 * Return SCSI status or TCMU_STS_NOT_HANDLED
 */
static inline int
_zbc_handle_cmd(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	uint8_t *cdb = cmd->cdb;
	struct iovec *iovec = cmd->iovec;
	size_t iov_cnt = cmd->iov_cnt;

	zdev->nr_cdb_cmds++;

	switch (cmd->cdb[0]) {

	case INQUIRY:
		return zbc_inquiry(dev, cmd);

	case TEST_UNIT_READY:
		zdev->nr_tur_cmds++;
		return tcmu_emulate_test_unit_ready(cdb, iovec, iov_cnt);

	case READ_CAPACITY:
		return zbc_read_capacity10(dev, cmd);

	case SERVICE_ACTION_IN_16:
		if (cdb[1] == READ_CAPACITY_16)
			return zbc_read_capacity16(dev, cmd);
		break;

	case MODE_SENSE:
	case MODE_SENSE_10:
		return zbc_mode_sense(dev, cmd);

	case MODE_SELECT:
	case MODE_SELECT_10:
		return zbc_mode_select(dev, cmd);

	case REQUEST_SENSE:
		return zbc_request_sense(dev, cmd);

	case ZBC_IN:
		return zbc_scsi_in(dev, cmd);

	case ZBC_OUT:
		return zbc_scsi_out(dev, cmd);

	case ZBC_ZONE_ACTIVATE_32:
		if (zbc_mt_zd(zdev))
			return zbc_scsi_zone_activate32(dev, cmd);
		break;

	case READ_6:
		break;
	case READ_10:
	case READ_12:
	case READ_16:
		return zbc_scsi_read(dev, cmd);

	case WRITE_6:
		break;
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		return zbc_scsi_write(dev, cmd);

	case SYNCHRONIZE_CACHE:
	case SYNCHRONIZE_CACHE_16:
		return zbc_flush(dev, cmd);

	case RECEIVE_DIAGNOSTIC_RESULTS:
		if (zbc_mt_zoned(zdev))
			return zbc_scsi_receive_diag(dev, cmd);

	case SANITIZE:
		return zbc_sanitize(dev, cmd);
	case FORMAT_UNIT:
		return zbc_format(dev, cmd);
	}

	zdev->nr_nh_cmds++;
	return TCMU_STS_NOT_HANDLED;
}

static int zbc_handle_cmd(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	int ret = _zbc_handle_cmd(dev, cmd);
	return ret;
}

static const char dhsmr_cfg_desc[] =
	"Zone Domains device emulator configuration string format:\n"
	"\"[opt1[/opt2][...]@]<backstore file path>\n"
	"Options:\n"
	"  model-<type>      : SMR service model. Type must be either HA for\n"
	"                      host aware or HM for host managed\n"
	"                      The default is host managed.\n"
	"  lba-<size(B)>     : LBA size in bytes (512 or 4096).\n"
	"                      The default is 512.\n"
	"  zsize-<size(MiB)> : Zone size in MiB. The default is 256 MiB.\n"
	"  conv-<num>        : Number of conventional zones at LBA 0 (can be 0)\n"
	"                      The default is 1%% of the device capacity.\n"
	"  open-<num>        : Maximum number of open zones.\n"
	"                      The default is 128.\n"
	"  rsize-<size(MiB)> : Zone realm size in MiB.\n"
	"                      The default is 10 zones.\n"
	"  sgain-<factor>    : SMR/CMR capacity gain factor.\n"
	"                      The default is 1.25.\n"
	"Ex:\n"
	"  cfgstring=zsize-128/rsize-1024@/var/local/hzbc.raw\n"
	"  will create a ZD disk with 128 MiB zones and 1024 MiB\n"
	"  zone domains, stored in the file /var/local/hzbc.raw\n";

static struct tcmur_handler dhsmr_handler = {
	.cfg_desc = dhsmr_cfg_desc,

	.name = "Zone Domains Emulation Handler",
	.subtype = ZBC_HANDLER_SUBTYPE,

	.open = zbc_open,
	.close = zbc_close,
	.handle_cmd = zbc_handle_cmd,
	.nr_threads = 0,
};

/*
 * Entry point must be named "handler_init".
 */
int handler_init(void)
{
	return tcmur_register_handler(&dhsmr_handler);
}
