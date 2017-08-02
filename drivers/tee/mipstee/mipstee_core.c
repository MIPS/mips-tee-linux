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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/errno.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/tee_drv.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include "mipstee_private.h"
#include "tipc_private.h"

#define DRIVER_NAME "mipstee"

#define MIPSTEE_SHM_NUM_PRIV_PAGES	1

#define TEE_SESS_MANAGER_COMMAND_MSG "tee.sess_manager.command_msg"

#define TEE_NULL_MEMREF (-1)

/**
 * mipstee_from_msg_param() - convert from MIPSTEE_MSG parameters to
 *			    struct tee_param
 * @params:	subsystem internal parameter representation
 * @num_params:	number of elements in the parameter arrays
 * @msg_params:	MIPSTEE_MSG parameters
 * Returns 0 on success or <0 on failure
 */
int mipstee_from_msg_param(struct tee_param *params, size_t num_params,
			 const struct mipstee_msg_param *msg_params)
{
	int rc;
	size_t n;
	struct tee_shm *shm;
	phys_addr_t pa;

	for (n = 0; n < num_params; n++) {
		struct tee_param *p = params + n;
		const struct mipstee_msg_param *mp = msg_params + n;
		u32 attr = mp->attr & MIPSTEE_MSG_ATTR_TYPE_MASK;

		switch (attr) {
		case MIPSTEE_MSG_ATTR_TYPE_NONE:
			p->attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
			memset(&p->u, 0, sizeof(p->u));
			break;
		case MIPSTEE_MSG_ATTR_TYPE_VALUE_INPUT:
		case MIPSTEE_MSG_ATTR_TYPE_VALUE_OUTPUT:
		case MIPSTEE_MSG_ATTR_TYPE_VALUE_INOUT:
			p->attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT +
				  attr - MIPSTEE_MSG_ATTR_TYPE_VALUE_INPUT;
			p->u.value.a = mp->u.value.a;
			p->u.value.b = mp->u.value.b;
			p->u.value.c = mp->u.value.c;
			break;
		case MIPSTEE_MSG_ATTR_TYPE_TMEM_INPUT:
		case MIPSTEE_MSG_ATTR_TYPE_TMEM_OUTPUT:
		case MIPSTEE_MSG_ATTR_TYPE_TMEM_INOUT:
			p->attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT +
				  attr - MIPSTEE_MSG_ATTR_TYPE_TMEM_INPUT;
			p->u.memref.size = (size_t)mp->u.tmem.size;
#if 1 // TODO XXX tee-supplicant use-case not implemented
			(void)pa;
			(void)shm;
			(void)rc;

#else
			shm = (struct tee_shm *)(unsigned long)
				mp->u.tmem.shm_ref;
			if (!shm) {
				p->u.memref.shm_offs = 0;
				p->u.memref.shm = NULL;
				break;
			}
			rc = tee_shm_get_pa(shm, 0, &pa);
			if (rc)
				return rc;

			p->u.memref.shm_offs = mp->u.tmem.buf_ptr - pa +
				mipstee->shm_base;
			p->u.memref.shm = shm;

			pr_devel("%s memref pa %x sz %llx buf_ptr %llx\n",
					__func__, pa, mp->u.tmem.size,
					mp->u.tmem.buf_ptr);

			/* Check that the memref is covered by the shm object */
			if (p->u.memref.size) {
				size_t o = p->u.memref.shm_offs +
					   p->u.memref.size - 1;

				rc = tee_shm_get_pa(shm, o, NULL);
				if (rc)
					return rc;
			}
#endif
			break;
		default:
			pr_devel("%s error: %zu of %u num_params, attr %x\n",
					__func__, n, num_params, attr);
			return -EINVAL;
		}
	}
	return 0;
}

/**
 * mipstee_to_msg_param() - convert from struct tee_params to MIPSTEE_MSG parameters
 * @msg_params:	MIPSTEE_MSG parameters
 * @num_params:	number of elements in the parameter arrays
 * @params:	subsystem itnernal parameter representation
 * @shm_base:	base address of TEE shm region or NULL
 * Returns 0 on success or <0 on failure
 */
int mipstee_to_msg_param(struct mipstee_msg_param *msg_params, size_t num_params,
		const struct tee_param *params, const phys_addr_t shm_base)
{
	int rc;
	size_t n;
	phys_addr_t pa;

	for (n = 0; n < num_params; n++) {
		const struct tee_param *p = params + n;
		struct mipstee_msg_param *mp = msg_params + n;

		switch (p->attr) {
		case TEE_IOCTL_PARAM_ATTR_TYPE_NONE:
			mp->attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
			memset(&mp->u, 0, sizeof(mp->u));
			break;
		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT:
			mp->attr = MIPSTEE_MSG_ATTR_TYPE_VALUE_INPUT + p->attr -
				   TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
			mp->u.value.a = p->u.value.a;
			mp->u.value.b = p->u.value.b;
			mp->u.value.c = p->u.value.c;
			break;
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT:
			mp->attr = MIPSTEE_MSG_ATTR_TYPE_TMEM_INPUT +
				   p->attr -
				   TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;
			mp->u.tmem.shm_ref = (unsigned long)p->u.memref.shm;
			mp->u.tmem.size = p->u.memref.size;
			if (!p->u.memref.shm) {
				mp->u.tmem.buf_ptr = 0;
				break;
			}
			/*
			 * The generic tee_core api detects invalid shm objects
			 * and so we can't hit the (!p->u.memref.shm) condition
			 * above.  Instead use shm_offs and size to detect a
			 * NULL memref and pass it on to TA.
			 */
			if ((p->u.memref.shm_offs == (size_t)TEE_NULL_MEMREF)
					&& !p->u.memref.size) {
				mp->u.tmem.buf_ptr = 0;
				break;
			}

			rc = tee_shm_get_pa(p->u.memref.shm,
					    p->u.memref.shm_offs, &pa);
			if (rc)
				return rc;

			mp->u.tmem.buf_ptr = pa - shm_base;

			pr_devel("%s memref pa %x sz %llx buf_ptr %llx\n",
					__func__, pa, mp->u.tmem.size,
					mp->u.tmem.buf_ptr);

			mp->attr |= MIPSTEE_MSG_ATTR_CACHE_PREDEFINED <<
					MIPSTEE_MSG_ATTR_CACHE_SHIFT;
			break;
		default:
			return -EINVAL;
		}
	}
	return 0;
}

static void mipstee_get_version(struct tee_device *teedev,
			      struct tee_ioctl_version_data *vers)
{
	struct tee_ioctl_version_data v = {
		.impl_id = TEE_IMPL_ID_MIPSTEE,
		.impl_caps = TEE_MIPSTEE_CAP_VZ,
		.gen_caps = TEE_GEN_CAP_GP,
	};
	*vers = v;
}

static int mipstee_connect(struct tee_context *ctx,
		struct tipc_dn_chan **channel, const char *srv_name)
{
	struct tee_device *teedev = ctx->teedev;
	struct mipstee *mipstee = tee_get_drvdata(teedev);
	int rc;

	rc = tipc_open(mipstee->trusty_dev, channel);
	if (rc)
		goto err;

	rc = tipc_connect(*channel, srv_name);
	if (rc)
		goto err_release;

	return 0;

err_release:
	tipc_release(*channel);
err:
	return rc;
}

static int mipstee_open(struct tee_context *ctx)
{
	struct mipstee_context_data *ctxdata;
	int rc;

	pr_devel("%s ctx %p\n", __func__, ctx);

	ctxdata = kzalloc(sizeof(*ctxdata), GFP_KERNEL);
	if (!ctxdata)
		return -ENOMEM;

	mutex_init(&ctxdata->mutex);
	INIT_LIST_HEAD(&ctxdata->sess_list);

	rc = mipstee_connect(ctx, &ctxdata->cmd_ch,
			TEE_SESS_MANAGER_COMMAND_MSG);
	if (rc)
		goto err;

	ctx->data = ctxdata;
	return 0;

err:
	kfree(ctxdata);
	return rc;
}

static void mipstee_release(struct tee_context *ctx)
{
	struct mipstee_context_data *ctxdata = ctx->data;
	struct tee_shm *shm;
	struct mipstee_msg_arg *arg = NULL;
	struct mipstee_session *sess;
	struct mipstee_session *sess_tmp;

	pr_devel("%s ctx %p\n", __func__, ctx);

	if (!ctxdata)
		return;

	shm = tee_shm_alloc(ctx, sizeof(struct mipstee_msg_arg), TEE_SHM_MAPPED);
	if (!IS_ERR(shm)) {
		arg = tee_shm_get_va(shm, 0);
		/*
		 * If IS_ERR(arg) for some reason, we can't call
		 * mipstee_close_session(), only free the memory. TEE will leak
		 * sessions and finally refuse more sessions, but we will at
		 * least let REE reclaim its memory.
		 */
	}

	list_for_each_entry_safe(sess, sess_tmp, &ctxdata->sess_list,
				 list_node) {
		list_del(&sess->list_node);
		if (!IS_ERR_OR_NULL(arg)) {
			memset(arg, 0, sizeof(*arg));
			arg->cmd = MIPSTEE_MSG_CMD_CLOSE_SESSION;
			arg->session = sess->session_id;
			arg->func = MIPSTEE_MSG_CMD_CANCEL;
			mipstee_do_call_with_arg(ctx, arg);
		}
		kfree(sess);
	}

	tipc_release(ctxdata->cmd_ch);
	ctxdata->cmd_ch = NULL;
	kfree(ctxdata);

	if (!IS_ERR(shm))
		tee_shm_free(shm);

	ctx->data = NULL;
}

static struct tee_driver_ops mipstee_ops = {
	.get_version = mipstee_get_version,
	.open = mipstee_open,
	.release = mipstee_release,
	.open_session = mipstee_open_session,
	.close_session = mipstee_close_session,
	.invoke_func = mipstee_invoke_func,
	.cancel_req = mipstee_cancel_req,
};

static struct tee_desc mipstee_desc = {
	.name = DRIVER_NAME "-clnt",
	.ops = &mipstee_ops,
	.owner = THIS_MODULE,
};

static int mipstee_shm_of_probe(struct mipstee *mipstee)
{
	struct device_node *of_dn;
	struct device_node *dn;
	const __be32 *addr_p;
	u64 sz64, addr64;
	unsigned int flags;
	int rc = 0;

	/*
	 * query the DT node of the virtio mmio device which parented this
	 * tee device for its associated shared memory node
	 */
	of_dn = dev_of_node(mipstee->dev->parent);

	dn = of_parse_phandle(of_dn, "trusty,shmem", 0);
	if (!of_device_is_available(dn) ||
			!of_device_is_compatible(dn, "trusty-shmem")) {
		pr_err("trusty-shmem DT node not available\n");
		rc = -ENODEV;
		goto out_node_put;
	}

	addr_p = of_get_address(dn, 0, &sz64, &flags);
	if (!addr_p || !sz64) {
		pr_err("trusty-shmem DT node reg not available\n");
		rc = -ENODEV;
		goto out_node_put;
	}
	pr_devel("trusty-shmem DT addr %x sz64 %llx flags %x\n",
			be32_to_cpu(*addr_p), sz64, flags);

	addr64 = of_translate_address(dn, addr_p);
	if (!addr64) {
		pr_err("trusty-shmem DT node addr translate failed\n");
		rc = -ENODEV;
		goto out_node_put;
	}

	/* validate DT shm_base */
	if (sizeof(phys_addr_t) != sizeof(addr64)) {
		if ((phys_addr_t)addr64 != addr64) {
			pr_err("trusty-shmem DT shm_base addr overflow\n");
			rc = -ENODEV;
			goto out_node_put;
		}
	}

	/* memref pointers passed to TEE are offsets relative to shm_base */
	mipstee->shm_base = (phys_addr_t)addr64;
	mipstee->shm_size = (size_t)sz64;

	pr_devel("trusty-shmem base %p sz %zu\n", (void *)mipstee->shm_base,
			mipstee->shm_size);

out_node_put:
	of_node_put(dn);
	if (rc) {
		pr_info("No valid trusty-shmem DT data\n");
		mipstee->shm_base = 0;
		mipstee->shm_size = 0;
	}
	return rc;
}

static int mipstee_shm_alloc(struct mipstee *mipstee)
{
	return mipstee_shm_of_probe(mipstee);
}

static int mipstee_config_shm_memremap(struct mipstee *mipstee)
{
	int rc;
	struct tee_shm_pool *pool = NULL;
	unsigned long vaddr;
	phys_addr_t paddr;
	size_t size;
	phys_addr_t begin, end;
	void *va;
	struct tee_shm_pool_mem_info priv_info;
	struct tee_shm_pool_mem_info dmabuf_info;

	rc = mipstee_shm_alloc(mipstee);
	if (rc) {
		pr_err("shared memory allocation failed %d\n", rc);
		return rc;
	}

	begin = roundup(mipstee->shm_base, PAGE_SIZE);
	end = rounddown(mipstee->shm_base + mipstee->shm_size, PAGE_SIZE);
	paddr = begin;
	size = end - begin;

	if (size < 2 * MIPSTEE_SHM_NUM_PRIV_PAGES * PAGE_SIZE) {
		pr_err("shared memory area too small\n");
		return -EINVAL;
	}

	va = memremap(paddr, size, MEMREMAP_WB);
	if (!va) {
		pr_err("shared memory ioremap failed\n");
		return -EINVAL;
	}
	vaddr = (unsigned long)va;

	pr_info("SHM base pa %p va %p sz %x\n", (void*)paddr, va, size);

	priv_info.vaddr = vaddr;
	priv_info.paddr = paddr;
	priv_info.size = MIPSTEE_SHM_NUM_PRIV_PAGES * PAGE_SIZE;
	dmabuf_info.vaddr = vaddr + MIPSTEE_SHM_NUM_PRIV_PAGES * PAGE_SIZE;
	dmabuf_info.paddr = paddr + MIPSTEE_SHM_NUM_PRIV_PAGES * PAGE_SIZE;
	dmabuf_info.size = size - MIPSTEE_SHM_NUM_PRIV_PAGES * PAGE_SIZE;

	pool = tee_shm_pool_alloc_res_mem(&priv_info, &dmabuf_info);
	if (IS_ERR(pool)) {
		memunmap(va);
		return PTR_ERR(pool);
	}

	mipstee->memremaped_shm = va;
	mipstee->pool = pool;

	return 0;
}

static void mipstee_release_shm(struct mipstee *mipstee)
{
	if (!mipstee)
		return;

	if (mipstee->pool) {
		tee_shm_pool_free(mipstee->pool);
		mipstee->pool = NULL;
	}
	if (mipstee->memremaped_shm) {
		memunmap(mipstee->memremaped_shm);
		mipstee->memremaped_shm = NULL;
	}
}

static struct mipstee *mipstee_probe(struct device *parent)
{
	struct mipstee *mipstee = NULL;
	struct tee_device *teedev;
	int rc;

	mipstee = kzalloc(sizeof(*mipstee), GFP_KERNEL);
	if (!mipstee)
		return ERR_PTR(-ENOMEM);

	mipstee->dev = parent;

	rc = mipstee_config_shm_memremap(mipstee);
	if (rc)
		goto err;

	teedev = tee_device_alloc(&mipstee_desc, NULL, mipstee->pool, mipstee);
	if (IS_ERR(teedev)) {
		rc = PTR_ERR(teedev);
		goto err;
	}
	mipstee->teedev = teedev;

	rc = tee_device_register(mipstee->teedev);
	if (rc)
		goto err;

	pr_info("driver initialized\n");
	return mipstee;

err:
	/*
	 * tee_device_unregister() is safe to call even if the devices hasn't
	 * been registered with tee_device_register() yet.
	 */
	tee_device_unregister(mipstee->teedev);
	mipstee_release_shm(mipstee);
	kfree(mipstee);

	return ERR_PTR(rc);
}

static void mipstee_remove(struct mipstee *mipstee)
{
	/*
	 * The two devices has to be unregistered before we can free the
	 * other resources.
	 */
	tee_device_unregister(mipstee->teedev);

	mipstee_release_shm(mipstee);

	kfree(mipstee);
}

void *mipstee_create_cdev_node(struct device *parent, struct tipc_cdev_node *trusty_dev)
{
	struct mipstee *mipstee;

	mipstee = mipstee_probe(parent);
	if (IS_ERR(mipstee))
		return ERR_CAST(mipstee);

	mipstee->trusty_dev = trusty_dev;
	return mipstee;
}

void mipstee_delete_cdev_node(void *cdev_handle)
{
	struct mipstee *mipstee = (struct mipstee*)cdev_handle;

	if (mipstee)
		mipstee_remove(mipstee);
}
