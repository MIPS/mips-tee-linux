/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2017-2018, MIPS Tech, LLC and/or its affiliated group companies
 * (“MIPS”).
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef MIPSTEE_PRIVATE_H
#define MIPSTEE_PRIVATE_H

#include <linux/semaphore.h>
#include <linux/tee_drv.h>
#include <linux/types.h>
#include "mipstee_msg.h"
#include "tipc_private.h"

/* Some Global Platform error codes used in this driver */
#define TEEC_SUCCESS			0x00000000
#define TEEC_ERROR_BAD_PARAMETERS	0xFFFF0006
#define TEEC_ERROR_COMMUNICATION	0xFFFF000E
#define TEEC_ERROR_OUT_OF_MEMORY	0xFFFF000C

#define TEEC_ORIGIN_COMMS		0x00000002

/* Global Platform TEEC_LOGIN_TYPES */
#define TEEC_LOGIN_PUBLIC               0x00000000
#define TEEC_LOGIN_USER                 0x00000001
#define TEEC_LOGIN_GROUP                0x00000002
#define TEEC_LOGIN_APPLICATION          0x00000004
#define TEEC_LOGIN_USER_APPLICATION     0x00000005
#define TEEC_LOGIN_GROUP_APPLICATION    0x00000006

/**
 * struct mipstee - main service struct
 * @dev:		parent virtio tee device
 * @teedev:		client device
 * @trusty_dev		map mipstee device to trusty ipc virtio device
 * @pool:		shared memory pool
 * @memremaped_shm	virtual address of memory in shared memory pool
 * @shm_base		base address of TEE shm from DTB
 * @shm_size		size of TEE shm
 */
struct mipstee {
	struct device *dev;
	struct tee_device *teedev;
	struct tipc_cdev_node *trusty_dev;
	struct tee_shm_pool *pool;
	void *memremaped_shm;
	phys_addr_t shm_base;
	size_t shm_size;
};

struct mipstee_session {
	struct list_head list_node;
	u32 session_id;
};

struct mipstee_context_data {
	/* Serializes access to this struct */
	struct mutex mutex;
	struct list_head sess_list;
	struct tipc_dn_chan *cmd_ch;
};

u32 mipstee_do_call_with_arg(struct tee_context *ctx,
			     struct mipstee_msg_arg *msg_arg);
int mipstee_open_session(struct tee_context *ctx,
		       struct tee_ioctl_open_session_arg *arg,
		       struct tee_param *param);
int mipstee_close_session(struct tee_context *ctx, u32 session);
int mipstee_invoke_func(struct tee_context *ctx, struct tee_ioctl_invoke_arg *arg,
		      struct tee_param *param);
int mipstee_cancel_req(struct tee_context *ctx, u32 cancel_id, u32 session);

int mipstee_from_msg_param(struct tee_param *params, size_t num_params,
			 const struct mipstee_msg_param *msg_params);
int mipstee_to_msg_param(struct mipstee_msg_param *msg_params, size_t num_params,
		const struct tee_param *params, const phys_addr_t shm_base);

void *mipstee_create_cdev_node(struct device *parent,
				struct tipc_cdev_node *trusty_dev);
void mipstee_delete_cdev_node(void *cdev_handle);

#endif /*MIPSTEE_PRIVATE_H*/
