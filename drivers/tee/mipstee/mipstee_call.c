/*
 * Copyright (c) 2017-2018, MIPS Tech, LLC and/or its affiliated group companies
 * (“MIPS”).
 * Copyright (c) 2015, Linaro Limited
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
#include <linux/device.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/tee_drv.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/fs.h>
#include "mipstee_private.h"
#include "tipc_private.h"

/* Requires the filpstate mutex to be held */
static struct mipstee_session *find_session(struct mipstee_context_data *ctxdata,
					  u32 session_id)
{
	struct mipstee_session *sess;

	list_for_each_entry(sess, &ctxdata->sess_list, list_node)
		if (sess->session_id == session_id)
			return sess;

	return NULL;
}

/**
 * mipstee_do_call_with_arg() - Send message to TEE
 * @ctx:	calling context
 * @msg_arg:	ptr to message to send
 *
 * Returns 0 on success or <0 on failure
 */
u32 mipstee_do_call_with_arg(struct tee_context *ctx,
			     struct mipstee_msg_arg *msg_arg)
{
	struct mipstee_context_data *ctxdata = ctx->data;
	struct tipc_dn_chan *channel = ctxdata->cmd_ch;
	struct kvec iov;
	struct iov_iter iter;
	int rc;

	pr_devel("%s ctx %p sess %u\n", __func__, ctx, msg_arg->session);

	iov.iov_base = msg_arg;
	iov.iov_len = MIPSTEE_MSG_GET_ARG_SIZE(msg_arg->num_params);

	// read from iov iter and write to tipc chan
	iov_iter_kvec(&iter, READ | ITER_KVEC, &iov, 1, iov.iov_len);
	rc = tipc_write_iter(channel, &iter);
	if (rc < 0) {
		pr_err("%s tipc_write_iter cmd %u sess %u err %d\n", __func__,
				msg_arg->cmd, msg_arg->session, rc);
		return rc;
	}

	if (msg_arg->cmd != MIPSTEE_MSG_CMD_CANCEL) {
		// read from tipc chan and write to iov iter
		iov_iter_kvec(&iter, WRITE | ITER_KVEC, &iov, 1, iov.iov_len);
		rc = tipc_read_iter(channel, &iter);
		if (rc < 0) {
			pr_err("%s tipc_read_iter cmd %u sess %u err %d\n",
					__func__, msg_arg->cmd,
					msg_arg->session, rc);
			return rc;
		}
	}

	return 0;
}

static struct tee_shm *get_msg_arg(struct tee_context *ctx, size_t num_params,
				   struct mipstee_msg_arg **msg_arg,
				   phys_addr_t *msg_parg)
{
	int rc;
	struct tee_shm *shm;
	struct mipstee_msg_arg *ma;

	shm = tee_shm_alloc(ctx, MIPSTEE_MSG_GET_ARG_SIZE(num_params),
			    TEE_SHM_MAPPED);
	if (IS_ERR(shm))
		return shm;

	ma = tee_shm_get_va(shm, 0);
	if (IS_ERR(ma)) {
		rc = PTR_ERR(ma);
		goto out;
	}

	rc = tee_shm_get_pa(shm, 0, msg_parg);
	if (rc)
		goto out;

	memset(ma, 0, MIPSTEE_MSG_GET_ARG_SIZE(num_params));
	ma->num_params = num_params;
	*msg_arg = ma;
out:
	if (rc) {
		tee_shm_free(shm);
		return ERR_PTR(rc);
	}

	return shm;
}

int mipstee_open_session(struct tee_context *ctx,
		       struct tee_ioctl_open_session_arg *arg,
		       struct tee_param *param)
{
	struct mipstee_context_data *ctxdata = ctx->data;
	struct mipstee *mipstee = tee_get_drvdata(ctx->teedev);
	int rc;
	struct tee_shm *shm;
	struct mipstee_msg_arg *msg_arg;
	struct mipstee_session *sess = NULL;

	pr_devel("%s ctx %p\n", __func__, ctx);

	/* +2 for the meta parameters added below */
	shm = get_msg_arg(ctx, arg->num_params + 2, &msg_arg, NULL);
	if (IS_ERR(shm))
		return PTR_ERR(shm);

	msg_arg->cmd = MIPSTEE_MSG_CMD_OPEN_SESSION;
	msg_arg->cancel_id = arg->cancel_id;

	/*
	 * Initialize and add the meta parameters needed when opening a
	 * session.
	 */
	msg_arg->params[0].attr = MIPSTEE_MSG_ATTR_TYPE_VALUE_INPUT |
				  MIPSTEE_MSG_ATTR_META;
	msg_arg->params[1].attr = MIPSTEE_MSG_ATTR_TYPE_VALUE_INPUT |
				  MIPSTEE_MSG_ATTR_META;
	memcpy(&msg_arg->params[0].u.value, arg->uuid, sizeof(arg->uuid));
	memcpy(&msg_arg->params[1].u.value, arg->clnt_uuid, sizeof(arg->clnt_uuid));
	msg_arg->params[1].u.value.c = arg->clnt_login;

	rc = mipstee_to_msg_param(msg_arg->params + 2, arg->num_params,
			param, mipstee->shm_base);
	if (rc)
		goto out;

	sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (!sess) {
		rc = -ENOMEM;
		goto out;
	}

	if (mipstee_do_call_with_arg(ctx, msg_arg)) {
		msg_arg->ret = TEEC_ERROR_COMMUNICATION;
		msg_arg->ret_origin = TEEC_ORIGIN_COMMS;
	}

	if (msg_arg->ret == TEEC_SUCCESS) {
		/* A new session has been created, add it to the list. */
		sess->session_id = msg_arg->session;
		mutex_lock(&ctxdata->mutex);
		list_add(&sess->list_node, &ctxdata->sess_list);
		mutex_unlock(&ctxdata->mutex);
	} else {
		kfree(sess);
	}

	if (mipstee_from_msg_param(param, arg->num_params, msg_arg->params + 2)) {
		pr_devel("%s msg_param error ctx %p sess %u ret code %x\n",
				__func__, ctx, msg_arg->session, msg_arg->ret);
		arg->ret = TEEC_ERROR_COMMUNICATION;
		arg->ret_origin = TEEC_ORIGIN_COMMS;
		/* Close session again to avoid leakage */
		mipstee_close_session(ctx, msg_arg->session);
	} else {
		arg->session = msg_arg->session;
		arg->ret = msg_arg->ret;
		arg->ret_origin = msg_arg->ret_origin;
	}
out:
	tee_shm_free(shm);

	pr_devel("%s done ctx %p sess %u\n", __func__, ctx, arg->session);
	return rc;
}

int mipstee_close_session(struct tee_context *ctx, u32 session)
{
	struct mipstee_context_data *ctxdata = ctx->data;
	struct tee_shm *shm;
	struct mipstee_msg_arg *msg_arg;
	struct mipstee_session *sess;

	pr_devel("%s ctx %p sess %u\n", __func__, ctx, session);

	/* Check that the session is valid and remove it from the list */
	mutex_lock(&ctxdata->mutex);
	sess = find_session(ctxdata, session);
	if (sess)
		list_del(&sess->list_node);
	mutex_unlock(&ctxdata->mutex);
	if (!sess)
		return -EINVAL;
	kfree(sess);

	shm = get_msg_arg(ctx, 0, &msg_arg, NULL);
	if (IS_ERR(shm))
		return PTR_ERR(shm);

	msg_arg->cmd = MIPSTEE_MSG_CMD_CLOSE_SESSION;
	msg_arg->session = session;
	mipstee_do_call_with_arg(ctx, msg_arg);

	tee_shm_free(shm);
	pr_devel("%s done ctx %p\n", __func__, ctx);
	return 0;
}

int mipstee_invoke_func(struct tee_context *ctx, struct tee_ioctl_invoke_arg *arg,
		      struct tee_param *param)
{
	struct mipstee_context_data *ctxdata = ctx->data;
	struct mipstee *mipstee = tee_get_drvdata(ctx->teedev);
	struct tee_shm *shm;
	struct mipstee_msg_arg *msg_arg;
	struct mipstee_session *sess;
	int rc;

	pr_devel("%s ctx %p sess %u\n", __func__, ctx, arg->session);

	/* Check that the session is valid */
	mutex_lock(&ctxdata->mutex);
	sess = find_session(ctxdata, arg->session);
	mutex_unlock(&ctxdata->mutex);
	if (!sess)
		return -EINVAL;

	shm = get_msg_arg(ctx, arg->num_params, &msg_arg, NULL);
	if (IS_ERR(shm))
		return PTR_ERR(shm);
	msg_arg->cmd = MIPSTEE_MSG_CMD_INVOKE_COMMAND;
	msg_arg->func = arg->func;
	msg_arg->session = arg->session;
	msg_arg->cancel_id = arg->cancel_id;

	rc = mipstee_to_msg_param(msg_arg->params, arg->num_params,
			param, mipstee->shm_base);
	if (rc)
		goto out;

	if (mipstee_do_call_with_arg(ctx, msg_arg)) {
		msg_arg->ret = TEEC_ERROR_COMMUNICATION;
		msg_arg->ret_origin = TEEC_ORIGIN_COMMS;
	}

	if (mipstee_from_msg_param(param, arg->num_params, msg_arg->params)) {
		msg_arg->ret = TEEC_ERROR_COMMUNICATION;
		msg_arg->ret_origin = TEEC_ORIGIN_COMMS;
	}

	arg->ret = msg_arg->ret;
	arg->ret_origin = msg_arg->ret_origin;
out:
	tee_shm_free(shm);
	pr_devel("%s done ctx %p\n", __func__, ctx);
	return rc;
}

int mipstee_cancel_req(struct tee_context *ctx, u32 cancel_id, u32 session)
{
	struct mipstee_context_data *ctxdata = ctx->data;
	struct tee_shm *shm;
	struct mipstee_msg_arg *msg_arg;
	struct mipstee_session *sess;

	pr_devel("%s ctx %p sess %u\n", __func__, ctx, session);

	/*
	 * For open session a session does not yet exist; Check that the
	 * session is valid if it's provided.
	 */
	if (session) {
		mutex_lock(&ctxdata->mutex);
		sess = find_session(ctxdata, session);
		mutex_unlock(&ctxdata->mutex);
		if (!sess)
			return -EINVAL;
	}

	shm = get_msg_arg(ctx, 0, &msg_arg, NULL);
	if (IS_ERR(shm))
		return PTR_ERR(shm);

	msg_arg->cmd = MIPSTEE_MSG_CMD_CANCEL;
	msg_arg->session = session;
	msg_arg->cancel_id = cancel_id;
	mipstee_do_call_with_arg(ctx, msg_arg);

	tee_shm_free(shm);
	return 0;
}
