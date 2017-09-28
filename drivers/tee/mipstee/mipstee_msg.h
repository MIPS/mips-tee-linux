/*
 * Copyright (c) 2017-2018, MIPS Tech, LLC and/or its affiliated group companies
 * (“MIPS”).
 * Copyright (c) 2015-2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _MIPSTEE_MSG_H
#define _MIPSTEE_MSG_H

#include <linux/bitops.h>
#include <linux/types.h>

/*
 * This file defines the MIPS-TEE message protocol used to communicate
 * with an instance of MIPS-TEE running in TEE.
 *
 * This file is divided into three sections.
 * 1. Formatting of messages.
 * 2. Requests from REE
 * 3. Requests from TEE, Remote Procedure Call (RPC), handled by
 *    tee-supplicant.
 */

/*****************************************************************************
 * Part 1 - formatting of messages
 *****************************************************************************/

#define MIPSTEE_MSG_ATTR_TYPE_NONE		0x0
#define MIPSTEE_MSG_ATTR_TYPE_VALUE_INPUT	0x1
#define MIPSTEE_MSG_ATTR_TYPE_VALUE_OUTPUT	0x2
#define MIPSTEE_MSG_ATTR_TYPE_VALUE_INOUT	0x3
#define MIPSTEE_MSG_ATTR_TYPE_RMEM_INPUT	0x5
#define MIPSTEE_MSG_ATTR_TYPE_RMEM_OUTPUT	0x6
#define MIPSTEE_MSG_ATTR_TYPE_RMEM_INOUT	0x7
#define MIPSTEE_MSG_ATTR_TYPE_TMEM_INPUT	0x9
#define MIPSTEE_MSG_ATTR_TYPE_TMEM_OUTPUT	0xa
#define MIPSTEE_MSG_ATTR_TYPE_TMEM_INOUT	0xb

#define MIPSTEE_MSG_ATTR_TYPE_MASK		GENMASK(7, 0)

/*
 * Meta parameter to be absorbed by the Secure OS and not passed
 * to the Trusted Application.
 *
 * Currently only used with MIPSTEE_MSG_CMD_OPEN_SESSION.
 */
#define MIPSTEE_MSG_ATTR_META			BIT(8)

/*
 * The temporary shared memory object is not physically contigous and this
 * temp memref is followed by another fragment until the last temp memref
 * that doesn't have this bit set.
 */
#define MIPSTEE_MSG_ATTR_FRAGMENT		BIT(9)

/*
 * Memory attributes for caching passed with temp memrefs. The actual value
 * used is defined outside the message protocol with the exception of
 * MIPSTEE_MSG_ATTR_CACHE_PREDEFINED which means the attributes already
 * defined for the memory range should be used.
 */
#define MIPSTEE_MSG_ATTR_CACHE_SHIFT		16
#define MIPSTEE_MSG_ATTR_CACHE_MASK		GENMASK(2, 0)
#define MIPSTEE_MSG_ATTR_CACHE_PREDEFINED	0

/*
 * Same values as TEE_LOGIN_* from TEE Internal API
 */
#define MIPSTEE_MSG_LOGIN_PUBLIC		0x00000000
#define MIPSTEE_MSG_LOGIN_USER			0x00000001
#define MIPSTEE_MSG_LOGIN_GROUP			0x00000002
#define MIPSTEE_MSG_LOGIN_APPLICATION		0x00000004
#define MIPSTEE_MSG_LOGIN_APPLICATION_USER	0x00000005
#define MIPSTEE_MSG_LOGIN_APPLICATION_GROUP	0x00000006

/**
 * struct mipstee_msg_param_tmem - temporary memory reference parameter
 * @buf_ptr:	Address of the buffer as an offset into shared memory.
 * @size:	Size of the buffer
 * @shm_ref:	Temporary shared memory reference, pointer to a struct tee_shm
 *
 * TEE and REE communicate using a predefined shared memory block.
 * Buffer pointers are passed as offsets into the shared memory block.
 */
struct mipstee_msg_param_tmem {
	u64 buf_ptr;
	u64 size;
	u64 shm_ref;
} __packed;

/**
 * struct mipstee_msg_param_rmem - registered memory reference parameter
 * @offs:	Offset into shared memory reference
 * @size:	Size of the buffer
 * @shm_ref:	Shared memory reference, pointer to a struct tee_shm
 */
struct mipstee_msg_param_rmem {
	u64 offs;
	u64 size;
	u64 shm_ref;
} __packed;

/**
 * struct mipstee_msg_param_value - opaque value parameter
 *
 * Value parameters are passed unchecked between normal and secure world.
 */
struct mipstee_msg_param_value {
	u64 a;
	u64 b;
	u64 c;
} __packed;

/**
 * struct mipstee_msg_param - parameter used together with struct
 * mipstee_msg_arg
 * @attr:	attributes
 * @tmem:	parameter by temporary memory reference
 * @rmem:	parameter by registered memory reference
 * @value:	parameter by opaque value
 *
 * @attr & MIPSTEE_MSG_ATTR_TYPE_MASK indicates if tmem, rmem or value is used
 * in the union.
 * MIPSTEE_MSG_ATTR_TYPE_VALUE_* indicates value,
 * MIPSTEE_MSG_ATTR_TYPE_TMEM_* indicates tmem and
 * MIPSTEE_MSG_ATTR_TYPE_RMEM_* indicates rmem.
 * MIPSTEE_MSG_ATTR_TYPE_NONE indicates that none of the members are used.
 */
struct mipstee_msg_param {
	u64 attr;
	union {
		struct mipstee_msg_param_tmem tmem;
		struct mipstee_msg_param_rmem rmem;
		struct mipstee_msg_param_value value;
	} u;
} __packed;

/**
 * struct mipstee_msg_arg - call argument
 * @cmd: Command, one of MIPSTEE_MSG_CMD_* or MIPSTEE_MSG_RPC_CMD_*
 * @func: Trusted Application function, specific to the Trusted Application,
 *	     used if cmd == MIPSTEE_MSG_CMD_INVOKE_COMMAND
 * @session: In parameter for all MIPSTEE_MSG_CMD_* except
 *	     MIPSTEE_MSG_CMD_OPEN_SESSION where it's an output parameter instead
 * @cancel_id: Cancellation id, a unique value to identify this request
 * @pad: not used
 * @ret: return value
 * @ret_origin: origin of the return value
 * @num_params: number of parameters supplied to the OS Command
 * @params: the parameters supplied to the OS Command
 *
 * All normal calls to Trusted OS uses this struct. If cmd requires further
 * information than what these field holds it can be passed as a parameter
 * tagged as meta (setting the MIPSTEE_MSG_ATTR_META bit in corresponding
 * attrs field). All parameters tagged as meta has to come first.
 *
 * Temp memref parameters can be fragmented if supported by the Trusted OS
 * If a logical memref parameter is fragmented then has all but the last
 * fragment the MIPSTEE_MSG_ATTR_FRAGMENT bit set in attrs. Even if a memref is
 * fragmented it will still be presented as a single logical memref to the
 * Trusted Application.
 */
struct mipstee_msg_arg {
	u32 cmd;
	u32 func;
	u32 session;
	u32 cancel_id;
	u32 pad;
	u32 ret;
	u32 ret_origin;
	u32 num_params;

	/* num_params tells the actual number of element in params */
	struct mipstee_msg_param params[0];
} __packed;

/**
 * MIPSTEE_MSG_GET_ARG_SIZE - return size of struct mipstee_msg_arg
 *
 * @num_params: Number of parameters embedded in the struct mipstee_msg_arg
 *
 * Returns the size of the struct mipstee_msg_arg together with the number
 * of embedded parameters.
 */
#define MIPSTEE_MSG_GET_ARG_SIZE(num_params) \
	(sizeof(struct mipstee_msg_arg) + \
	 sizeof(struct mipstee_msg_param) * (num_params))

/**
 * struct mipstee_msg_hdr
 * @magic    - set to REE_MAGIC
 * @data_tag - used to match synchronous requests and replies on the REE side
 */
struct mipstee_msg_hdr {
	uint32_t magic;
	uint32_t data_tag;
} __packed;

/**
 * struct mipstee_tipc_msg
 * @hdr - header for the message
 * @msg - the bulk of the sender's message
 */
struct mipstee_tipc_msg {
	struct mipstee_msg_hdr hdr;
	struct mipstee_msg_arg msg;
} __packed;

#define REE_MAGIC (0x52454520) /* "REE " */

#define MIPSTEE_TIPC_MSG_GET_SIZE(num_params) \
	(sizeof(struct mipstee_msg_hdr) + \
	 MIPSTEE_MSG_GET_ARG_SIZE(num_params))

/*****************************************************************************
 * Part 2 - requests from normal world
 *****************************************************************************/

/*
 * Return the following UID if using API specified in this file without
 * further extensions:
 * e9354b52-40d7-4195-9b0c-2536bf5c8773
 *
 * Represented in 4 32-bit words in MIPSTEE_MSG_UID_0, MIPSTEE_MSG_UID_1,
 * MIPSTEE_MSG_UID_2, MIPSTEE_MSG_UID_3.
 */
#define MIPSTEE_MSG_UID_0			0xe9354b52
#define MIPSTEE_MSG_UID_1			0x40d74195
#define MIPSTEE_MSG_UID_2			0x9b0c2536
#define MIPSTEE_MSG_UID_3			0xbf5c8773
#define MIPSTEE_MSG_FUNCID_CALLS_UID		0xFF01

/*
 * Returns 0.1 if using API specified in this file without further
 * extensions. Represented in 2 32-bit words in MIPSTEE_MSG_REVISION_MAJOR
 * and MIPSTEE_MSG_REVISION_MINOR
 */
#define MIPSTEE_MSG_REVISION_MAJOR		0
#define MIPSTEE_MSG_REVISION_MINOR		1
#define MIPSTEE_MSG_FUNCID_CALLS_REVISION	0xFF03

/*
 * Get UUID of Trusted OS.
 *
 * Used by non-secure world to figure out which Trusted OS is installed.
 * Note that returned UUID is the UUID of the Trusted OS, not of the API.
 *
 * MIPSTEE returns the following UID:
 * 1b8fb75c-40d7-4195-ad81-2536bf5c8773
 *
 * Returns UUID in 4 32-bit words in the same way as
 * MIPSTEE_MSG_FUNCID_CALLS_UID described above.
 *
 */
#define MIPSTEE_MSG_OS_MIPSTEE_UUID_0		0x1b8fb75c
#define MIPSTEE_MSG_OS_MIPSTEE_UUID_1		0x40d74195
#define MIPSTEE_MSG_OS_MIPSTEE_UUID_2		0xad812536
#define MIPSTEE_MSG_OS_MIPSTEE_UUID_3		0xbf5c8773
#define MIPSTEE_MSG_FUNCID_GET_OS_UUID		0x0000

/*
 * Get revision of Trusted OS.
 *
 * Used by non-secure world to figure out which version of the Trusted OS
 * is installed. Note that the returned revision is the revision of the
 * Trusted OS, not of the API.
 *
 * Returns revision in 2 32-bit words in the same way as
 * MIPSTEE_MSG_CALLS_REVISION described above.
 */
#define MIPSTEE_MSG_FUNCID_GET_OS_REVISION	0x0001

/*
 * Do a secure call with struct mipstee_msg_arg as argument
 * The MIPSTEE_MSG_CMD_* below defines what goes in struct mipstee_msg_arg::cmd
 *
 * MIPSTEE_MSG_CMD_OPEN_SESSION opens a session to a Trusted Application.
 * The first two parameters are tagged as meta, holding two value
 * parameters to pass the following information:
 * param[0].u.value.a-b uuid of Trusted Application
 * param[1].u.value.a-b uuid of Client
 * param[1].u.value.c Login class of client MIPSTEE_MSG_LOGIN_*
 *
 * MIPSTEE_MSG_CMD_INVOKE_COMMAND invokes a command a previously opened
 * session to a Trusted Application.  struct mipstee_msg_arg::func is Trusted
 * Application function, specific to the Trusted Application.
 *
 * MIPSTEE_MSG_CMD_CLOSE_SESSION closes a previously opened session to
 * Trusted Application.
 *
 * MIPSTEE_MSG_CMD_CANCEL cancels a currently invoked command.
 *
 * MIPSTEE_MSG_CMD_REGISTER_SHM registers a shared memory reference. The
 * information is passed as:
 * [in] param[0].attr			MIPSTEE_MSG_ATTR_TYPE_TMEM_INPUT
 *					[| MIPSTEE_MSG_ATTR_FRAGMENT]
 * [in] param[0].u.tmem.buf_ptr		physical address (of first fragment)
 * [in] param[0].u.tmem.size		size (of first fragment)
 * [in] param[0].u.tmem.shm_ref		holds shared memory reference
 * ...
 * The shared memory can optionally be fragmented, temp memrefs can follow
 * each other with all but the last with the MIPSTEE_MSG_ATTR_FRAGMENT bit set.
 *
 * MIPSTEE_MSG_CMD_UNREGISTER_SHM unregisteres a previously registered shared
 * memory reference. The information is passed as:
 * [in] param[0].attr			MIPSTEE_MSG_ATTR_TYPE_RMEM_INPUT
 * [in] param[0].u.rmem.shm_ref		holds shared memory reference
 * [in] param[0].u.rmem.offs		0
 * [in] param[0].u.rmem.size		0
 */
#define MIPSTEE_MSG_CMD_OPEN_SESSION		0
#define MIPSTEE_MSG_CMD_INVOKE_COMMAND		1
#define MIPSTEE_MSG_CMD_CLOSE_SESSION		2
#define MIPSTEE_MSG_CMD_CANCEL			3
#define MIPSTEE_MSG_CMD_REGISTER_SHM		4
#define MIPSTEE_MSG_CMD_UNREGISTER_SHM		5
#define MIPSTEE_MSG_FUNCID_CALL_WITH_ARG	0x0004

/*****************************************************************************
 * Part 3 - Requests from secure world, RPC
 *****************************************************************************/

/*
 * All RPC is done with a struct mipstee_msg_arg as bearer of information,
 * struct mipstee_msg_arg::arg holds values defined by MIPSTEE_MSG_RPC_CMD_* below
 *
 * RPC communication with tee-supplicant is reversed compared to normal
 * client communication desribed above. The supplicant receives requests
 * and sends responses.
 */

/*
 * Load a TA into memory, defined in tee-supplicant
 */
#define MIPSTEE_MSG_RPC_CMD_LOAD_TA		0

/*
 * Reserved
 */
#define MIPSTEE_MSG_RPC_CMD_RPMB		1

/*
 * File system access, defined in tee-supplicant
 */
#define MIPSTEE_MSG_RPC_CMD_FS			2

/*
 * Get time
 *
 * Returns number of seconds and nano seconds since the Epoch,
 * 1970-01-01 00:00:00 +0000 (UTC).
 *
 * [out] param[0].u.value.a	Number of seconds
 * [out] param[0].u.value.b	Number of nano seconds.
 */
#define MIPSTEE_MSG_RPC_CMD_GET_TIME		3

/*
 * Wait queue primitive, helper for secure world to implement a wait queue.
 *
 * If secure world need to wait for a secure world mutex it issues a sleep
 * request instead of spinning in secure world. Conversely is a wakeup
 * request issued when a secure world mutex with a thread waiting thread is
 * unlocked.
 *
 * Waiting on a key
 * [in] param[0].u.value.a MIPSTEE_MSG_RPC_WAIT_QUEUE_SLEEP
 * [in] param[0].u.value.b wait key
 *
 * Waking up a key
 * [in] param[0].u.value.a MIPSTEE_MSG_RPC_WAIT_QUEUE_WAKEUP
 * [in] param[0].u.value.b wakeup key
 */
#define MIPSTEE_MSG_RPC_CMD_WAIT_QUEUE		4
#define MIPSTEE_MSG_RPC_WAIT_QUEUE_SLEEP	0
#define MIPSTEE_MSG_RPC_WAIT_QUEUE_WAKEUP	1

/*
 * Suspend execution
 *
 * [in] param[0].value	.a number of milliseconds to suspend
 */
#define MIPSTEE_MSG_RPC_CMD_SUSPEND		5

/*
 * Allocate a piece of shared memory
 *
 * Shared memory can optionally be fragmented, to support that additional
 * spare param entries are allocated to make room for eventual fragments.
 * The spare param entries has .attr = MIPSTEE_MSG_ATTR_TYPE_NONE when
 * unused. All returned temp memrefs except the last should have the
 * MIPSTEE_MSG_ATTR_FRAGMENT bit set in the attr field.
 *
 * [in]  param[0].u.value.a		type of memory one of
 *					MIPSTEE_MSG_RPC_SHM_TYPE_* below
 * [in]  param[0].u.value.b		requested size
 * [in]  param[0].u.value.c		required alignment
 *
 * [out] param[0].u.tmem.buf_ptr	physical address (of first fragment)
 * [out] param[0].u.tmem.size		size (of first fragment)
 * [out] param[0].u.tmem.shm_ref	shared memory reference
 * ...
 * [out] param[n].u.tmem.buf_ptr	physical address
 * [out] param[n].u.tmem.size		size
 * [out] param[n].u.tmem.shm_ref	shared memory reference (same value
 *					as in param[n-1].u.tmem.shm_ref)
 */
#define MIPSTEE_MSG_RPC_CMD_SHM_ALLOC		6
/* Memory that can be shared with a non-secure user space application */
#define MIPSTEE_MSG_RPC_SHM_TYPE_APPL		0
/* Memory only shared with non-secure kernel */
#define MIPSTEE_MSG_RPC_SHM_TYPE_KERNEL		1

/*
 * Free shared memory previously allocated with MIPSTEE_MSG_RPC_CMD_SHM_ALLOC
 *
 * [in]  param[0].u.value.a		type of memory one of
 *					MIPSTEE_MSG_RPC_SHM_TYPE_* above
 * [in]  param[0].u.value.b		value of shared memory reference
 *					returned in param[0].u.tmem.shm_ref
 *					above
 */
#define MIPSTEE_MSG_RPC_CMD_SHM_FREE		7

#endif /* _MIPSTEE_MSG_H */
