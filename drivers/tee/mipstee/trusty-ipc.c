/*
 * Copyright (c) 2017-2018, MIPS Tech, LLC and/or its affiliated group companies
 * (“MIPS”).
 * Copyright (C) 2015 Google, Inc.
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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/idr.h>
#include <linux/completion.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/uio.h>

#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>

#include <linux/trusty/trusty_ipc.h>
#include "mipstee_private.h"

#define MAX_DEVICES			4

#define REPLY_TIMEOUT			5000
#define TXBUF_TIMEOUT			15000

#define MAX_SRV_NAME_LEN		256
#define MAX_DEV_NAME_LEN		32

#define DEFAULT_MSG_BUF_SIZE		PAGE_SIZE
#define DEFAULT_MSG_BUF_ALIGN		PAGE_SIZE

#define TIPC_CTRL_ADDR			53
#define TIPC_ANY_ADDR			0xFFFFFFFF

#define TIPC_MIN_LOCAL_ADDR		1024

#define MIPSTEE_TIPC_HDR_INIT		{ .magic = REE_MAGIC, .data_tag = 0 }

struct tipc_virtio_dev;

struct tipc_dev_config {
	u32 msg_buf_max_size;
	u32 msg_buf_alignment;
	char dev_name[MAX_DEV_NAME_LEN];
} __packed;

struct tipc_msg_hdr {
	u32 src;
	u32 dst;
	u32 reserved;
	u16 len;
	u16 flags;
	u8 data[0];
} __packed;

enum tipc_ctrl_msg_types {
	TIPC_CTRL_MSGTYPE_GO_ONLINE = 1,
	TIPC_CTRL_MSGTYPE_GO_OFFLINE,
	TIPC_CTRL_MSGTYPE_CONN_REQ,
	TIPC_CTRL_MSGTYPE_CONN_RSP,
	TIPC_CTRL_MSGTYPE_DISC_REQ,
};

struct tipc_ctrl_msg {
	u32 type;
	u32 body_len;
	u8  body[0];
} __packed;

struct tipc_conn_req_body {
	char name[MAX_SRV_NAME_LEN];
} __packed;

struct tipc_conn_rsp_body {
	u32 target;
	u32 status;
	u32 remote;
	u32 max_msg_size;
	u32 max_msg_cnt;
} __packed;

struct tipc_disc_req_body {
	u32 target;
} __packed;

struct tipc_cdev_node {
	void *cdev_handle;
	unsigned int minor;
};

enum tipc_device_state {
	VDS_OFFLINE = 0,
	VDS_ONLINE,
	VDS_DEAD,
};

struct tipc_virtio_dev {
	struct kref refcount;
	struct mutex lock; /* protects access to this device */
	struct virtio_device *vdev;
	struct virtqueue *rxvq;
	struct virtqueue *txvq;
	struct work_struct check_rxvq;
	struct work_struct check_txvq;
	struct workqueue_struct *check_wq;
	uint msg_buf_cnt;
	uint msg_buf_max_cnt;
	size_t msg_buf_max_sz;
	uint free_msg_buf_cnt;
	struct list_head free_buf_list;
	wait_queue_head_t sendq;
	struct idr addr_idr;
	enum tipc_device_state state;
	struct tipc_cdev_node cdev_node;
	char   cdev_name[MAX_DEV_NAME_LEN];
};

enum tipc_chan_state {
	TIPC_DISCONNECTED = 0,
	TIPC_CONNECTING,
	TIPC_CONNECTED,
	TIPC_STALE,
};

struct tipc_chan {
	struct mutex lock; /* protects channel state  */
	struct kref refcount;
	enum tipc_chan_state state;
	struct tipc_virtio_dev *vds;
	const struct tipc_chan_ops *ops;
	void *ops_arg;
	u32 remote;
	u32 local;
	u32 max_msg_size;
	u32 max_msg_cnt;
	char srv_name[MAX_SRV_NAME_LEN];
};

struct tag_data {
	struct iov_iter *iter;
	int tag;
	int r_ready;
	int r_err;
};

static struct class *tipc_class;
static unsigned int tipc_major;

struct virtio_device *default_vdev;

static DEFINE_IDR(tipc_devices);
static DEFINE_MUTEX(tipc_devices_lock);

static int _match_any(int id, void *p, void *data)
{
	return id;
}

static int _match_data(int id, void *p, void *data)
{
	return (p == data);
}

static void *_alloc_shareable_mem(size_t sz, phys_addr_t *ppa, gfp_t gfp)
{
	return alloc_pages_exact(sz, gfp);
}

static void _free_shareable_mem(size_t sz, void *va, phys_addr_t pa)
{
	free_pages_exact(va, sz);
}

static struct tipc_msg_buf *_alloc_msg_buf(size_t sz)
{
	struct tipc_msg_buf *mb;

	/* allocate tracking structure */
	mb = kzalloc(sizeof(struct tipc_msg_buf), GFP_KERNEL);
	if (!mb)
		return NULL;

	/* allocate buffer that can be shared with secure world */
	mb->buf_va = _alloc_shareable_mem(sz, &mb->buf_pa, GFP_KERNEL);
	if (!mb->buf_va)
		goto err_alloc;

	mb->buf_sz = sz;

	return mb;

err_alloc:
	kfree(mb);
	return NULL;
}

static void _free_msg_buf(struct tipc_msg_buf *mb)
{
	_free_shareable_mem(mb->buf_sz, mb->buf_va, mb->buf_pa);
	kfree(mb);
}

static void _free_msg_buf_list(struct list_head *list)
{
	struct tipc_msg_buf *mb = NULL;

	mb = list_first_entry_or_null(list, struct tipc_msg_buf, node);
	while (mb) {
		list_del(&mb->node);
		_free_msg_buf(mb);
		mb = list_first_entry_or_null(list, struct tipc_msg_buf, node);
	}
}

static inline void mb_reset(struct tipc_msg_buf *mb)
{
	mb->wpos = 0;
	mb->rpos = 0;
}

static void _free_chan(struct kref *kref)
{
	struct tipc_chan *ch = container_of(kref, struct tipc_chan, refcount);
	kfree(ch);
}

static void _free_vds(struct kref *kref)
{
	struct tipc_virtio_dev *vds =
		container_of(kref, struct tipc_virtio_dev, refcount);
	kfree(vds);
}

static struct tipc_msg_buf *vds_alloc_msg_buf(struct tipc_virtio_dev *vds)
{
	return _alloc_msg_buf(vds->msg_buf_max_sz);
}

static void vds_free_msg_buf(struct tipc_virtio_dev *vds,
			     struct tipc_msg_buf *mb)
{
	_free_msg_buf(mb);
}

static bool _put_txbuf_locked(struct tipc_virtio_dev *vds,
			      struct tipc_msg_buf *mb)
{
	list_add_tail(&mb->node, &vds->free_buf_list);
	return vds->free_msg_buf_cnt++ == 0;
}

static struct tipc_msg_buf *_get_txbuf_locked(struct tipc_virtio_dev *vds)
{
	struct tipc_msg_buf *mb;

	if (vds->state != VDS_ONLINE)
		return  ERR_PTR(-ENODEV);

	if (vds->free_msg_buf_cnt) {
		/* take it out of free list */
		mb = list_first_entry(&vds->free_buf_list,
				      struct tipc_msg_buf, node);
		list_del(&mb->node);
		vds->free_msg_buf_cnt--;
	} else {
		if (vds->msg_buf_cnt >= vds->msg_buf_max_cnt)
			return ERR_PTR(-EAGAIN);

		/* try to allocate it */
		mb = _alloc_msg_buf(vds->msg_buf_max_sz);
		if (!mb)
			return ERR_PTR(-ENOMEM);

		vds->msg_buf_cnt++;
	}
	return mb;
}

static struct tipc_msg_buf *_vds_get_txbuf(struct tipc_virtio_dev *vds)
{
	struct tipc_msg_buf *mb;

	mutex_lock(&vds->lock);
	mb = _get_txbuf_locked(vds);
	mutex_unlock(&vds->lock);

	return mb;
}

static void vds_put_txbuf(struct tipc_virtio_dev *vds, struct tipc_msg_buf *mb)
{
	if (!vds)
		return;

	mutex_lock(&vds->lock);
	_put_txbuf_locked(vds, mb);
	wake_up_interruptible(&vds->sendq);
	mutex_unlock(&vds->lock);
}

static struct tipc_msg_buf *vds_get_txbuf(struct tipc_virtio_dev *vds,
					  long timeout)
{
	struct tipc_msg_buf *mb;

	if (!vds)
		return ERR_PTR(-EINVAL);

	mb = _vds_get_txbuf(vds);

	if ((PTR_ERR(mb) == -EAGAIN) && timeout) {
		DEFINE_WAIT_FUNC(wait, woken_wake_function);

		timeout = msecs_to_jiffies(timeout);
		add_wait_queue(&vds->sendq, &wait);
		for (;;) {
			timeout = wait_woken(&wait, TASK_INTERRUPTIBLE,
					     timeout);
			if (!timeout) {
				mb = ERR_PTR(-ETIMEDOUT);
				break;
			}

			if (signal_pending(current)) {
				mb = ERR_PTR(-ERESTARTSYS);
				break;
			}

			mb = _vds_get_txbuf(vds);
			if (PTR_ERR(mb) != -EAGAIN)
				break;
		}
		remove_wait_queue(&vds->sendq, &wait);
	}

	if (IS_ERR(mb))
		return mb;

	BUG_ON(!mb);

	/* reset and reserve space for message header */
	mb_reset(mb);
	mb_put_data(mb, sizeof(struct tipc_msg_hdr));

	return mb;
}

static int vds_queue_txbuf(struct tipc_virtio_dev *vds,
			   struct tipc_msg_buf *mb)
{
	int err;
	struct scatterlist sg;
	bool need_notify = false;

	if (!vds)
		return -EINVAL;

	mutex_lock(&vds->lock);
	if (vds->state == VDS_ONLINE) {
		sg_init_one(&sg, mb->buf_va, mb->wpos);
		err = virtqueue_add_outbuf(vds->txvq, &sg, 1, mb, GFP_KERNEL);
		need_notify = virtqueue_kick_prepare(vds->txvq);
	} else {
		err = -ENODEV;
	}
	mutex_unlock(&vds->lock);

	if (need_notify)
		virtqueue_notify(vds->txvq);

	return err;
}

static int vds_add_channel(struct tipc_virtio_dev *vds,
			   struct tipc_chan *chan)
{
	int ret;

	mutex_lock(&vds->lock);
	if (vds->state == VDS_ONLINE) {
		ret = idr_alloc(&vds->addr_idr, chan,
				TIPC_MIN_LOCAL_ADDR, TIPC_ANY_ADDR - 1,
				GFP_KERNEL);
		if (ret > 0) {
			chan->local = ret;
			kref_get(&chan->refcount);
			ret = 0;
		}
	} else {
		ret = -EINVAL;
	}
	mutex_unlock(&vds->lock);

	return ret;
}

static void vds_del_channel(struct tipc_virtio_dev *vds,
			    struct tipc_chan *chan)
{
	mutex_lock(&vds->lock);
	if (chan->local) {
		idr_remove(&vds->addr_idr, chan->local);
		chan->local = 0;
		chan->remote = 0;
		kref_put(&chan->refcount, _free_chan);
	}
	mutex_unlock(&vds->lock);
}

static struct tipc_chan *vds_lookup_channel(struct tipc_virtio_dev *vds,
					    u32 addr)
{
	int id;
	struct tipc_chan *chan = NULL;

	mutex_lock(&vds->lock);
	if (addr == TIPC_ANY_ADDR) {
		id = idr_for_each(&vds->addr_idr, _match_any, NULL);
		if (id > 0)
			chan = idr_find(&vds->addr_idr, id);
	} else {
		chan = idr_find(&vds->addr_idr, addr);
	}
	if (chan)
		kref_get(&chan->refcount);
	mutex_unlock(&vds->lock);

	return chan;
}

static struct tipc_chan *vds_create_channel(struct tipc_virtio_dev *vds,
					    const struct tipc_chan_ops *ops,
					    void *ops_arg)
{
	int ret;
	struct tipc_chan *chan = NULL;

	if (!vds)
		return ERR_PTR(-ENOENT);

	if (!ops)
		return ERR_PTR(-EINVAL);

	chan = kzalloc(sizeof(*chan), GFP_KERNEL);
	if (!chan)
		return ERR_PTR(-ENOMEM);

	kref_get(&vds->refcount);
	chan->vds = vds;
	chan->ops = ops;
	chan->ops_arg = ops_arg;
	mutex_init(&chan->lock);
	kref_init(&chan->refcount);
	chan->state = TIPC_DISCONNECTED;

	ret = vds_add_channel(vds, chan);
	if (ret) {
		kfree(chan);
		kref_put(&vds->refcount, _free_vds);
		return ERR_PTR(ret);
	}

	return chan;
}

static void fill_msg_hdr(struct tipc_msg_buf *mb, u32 src, u32 dst)
{
	struct tipc_msg_hdr *hdr = mb_get_data(mb, sizeof(*hdr));

	hdr->src = src;
	hdr->dst = dst;
	hdr->len = mb_avail_data(mb);
	hdr->flags = 0;
	hdr->reserved = 0;
}

/*****************************************************************************/

struct tipc_chan *tipc_create_channel(struct device *dev,
				      const struct tipc_chan_ops *ops,
				      void *ops_arg)
{
	struct virtio_device *vd;
	struct tipc_chan *chan;
	struct tipc_virtio_dev *vds;

	mutex_lock(&tipc_devices_lock);
	if (dev) {
		vd = container_of(dev, struct virtio_device, dev);
	} else {
		vd = default_vdev;
		if (!vd) {
			mutex_unlock(&tipc_devices_lock);
			return ERR_PTR(-ENOENT);
		}
	}
	vds = vd->priv;
	kref_get(&vds->refcount);
	mutex_unlock(&tipc_devices_lock);

	chan = vds_create_channel(vds, ops, ops_arg);
	kref_put(&vds->refcount, _free_vds);
	return chan;
}
EXPORT_SYMBOL(tipc_create_channel);

struct tipc_msg_buf *tipc_chan_get_rxbuf(struct tipc_chan *chan)
{
	return vds_alloc_msg_buf(chan->vds);
}
EXPORT_SYMBOL(tipc_chan_get_rxbuf);

void tipc_chan_put_rxbuf(struct tipc_chan *chan, struct tipc_msg_buf *mb)
{
	vds_free_msg_buf(chan->vds, mb);
}
EXPORT_SYMBOL(tipc_chan_put_rxbuf);

struct tipc_msg_buf *tipc_chan_get_txbuf_timeout(struct tipc_chan *chan,
						 long timeout)
{
	return vds_get_txbuf(chan->vds, timeout);
}
EXPORT_SYMBOL(tipc_chan_get_txbuf_timeout);

void tipc_chan_put_txbuf(struct tipc_chan *chan, struct tipc_msg_buf *mb)
{
	vds_put_txbuf(chan->vds, mb);
}
EXPORT_SYMBOL(tipc_chan_put_txbuf);

int tipc_chan_queue_msg(struct tipc_chan *chan, struct tipc_msg_buf *mb)
{
	int err;

	mutex_lock(&chan->lock);
	switch (chan->state) {
	case TIPC_CONNECTED:
		fill_msg_hdr(mb, chan->local, chan->remote);
		err = vds_queue_txbuf(chan->vds, mb);
		if (err) {
			/* this should never happen */
			pr_err("%s: failed to queue tx buffer (%d)\n",
			       __func__, err);
		}
		break;
	case TIPC_DISCONNECTED:
	case TIPC_CONNECTING:
		err = -ENOTCONN;
		break;
	case TIPC_STALE:
		err = -ESHUTDOWN;
		break;
	default:
		err = -EBADFD;
		pr_err("%s: unexpected channel state %d\n",
		       __func__, chan->state);
	}
	mutex_unlock(&chan->lock);
	return err;
}
EXPORT_SYMBOL(tipc_chan_queue_msg);


int tipc_chan_connect(struct tipc_chan *chan, const char *name)
{
	int err;
	struct tipc_ctrl_msg *msg;
	struct tipc_conn_req_body *body;
	struct tipc_msg_buf *txbuf;

	txbuf = vds_get_txbuf(chan->vds, TXBUF_TIMEOUT);
	if (IS_ERR(txbuf))
		return PTR_ERR(txbuf);

	/* reserve space for connection request control message */
	msg = mb_put_data(txbuf, sizeof(*msg) + sizeof(*body));
	body = (struct tipc_conn_req_body *)msg->body;

	/* fill message */
	msg->type = TIPC_CTRL_MSGTYPE_CONN_REQ;
	msg->body_len  = sizeof(*body);

	strncpy(body->name, name, sizeof(body->name));
	body->name[sizeof(body->name)-1] = '\0';

	mutex_lock(&chan->lock);
	switch (chan->state) {
	case TIPC_DISCONNECTED:
		/* save service name we are connecting to */
		strcpy(chan->srv_name, body->name);

		fill_msg_hdr(txbuf, chan->local, TIPC_CTRL_ADDR);
		err = vds_queue_txbuf(chan->vds, txbuf);
		if (err) {
			/* this should never happen */
			pr_err("%s: failed to queue tx buffer (%d)\n",
			       __func__, err);
		} else {
			chan->state = TIPC_CONNECTING;
			txbuf = NULL; /* prevents discarding buffer */
		}
		break;
	case TIPC_CONNECTED:
	case TIPC_CONNECTING:
		/* check if we are trying to connect to the same service */
		if (strcmp(chan->srv_name, body->name) == 0)
			err = 0;
		else
			if (chan->state == TIPC_CONNECTING)
				err = -EALREADY; /* in progress */
			else
				err = -EISCONN;  /* already connected */
		break;

	case TIPC_STALE:
		err = -ESHUTDOWN;
		break;
	default:
		err = -EBADFD;
		pr_err("%s: unexpected channel state %d\n",
		       __func__, chan->state);
		break;
	}
	mutex_unlock(&chan->lock);

	if (txbuf)
		tipc_chan_put_txbuf(chan, txbuf); /* discard it */

	return err;
}
EXPORT_SYMBOL(tipc_chan_connect);

int tipc_chan_shutdown(struct tipc_chan *chan)
{
	int err;
	struct tipc_ctrl_msg *msg;
	struct tipc_disc_req_body *body;
	struct tipc_msg_buf *txbuf = NULL;

	/* get tx buffer */
	txbuf = vds_get_txbuf(chan->vds, TXBUF_TIMEOUT);
	if (IS_ERR(txbuf))
		return PTR_ERR(txbuf);

	mutex_lock(&chan->lock);
	if (chan->state == TIPC_CONNECTED || chan->state == TIPC_CONNECTING) {
		/* reserve space for disconnect request control message */
		msg = mb_put_data(txbuf, sizeof(*msg) + sizeof(*body));
		body = (struct tipc_disc_req_body *)msg->body;

		msg->type = TIPC_CTRL_MSGTYPE_DISC_REQ;
		msg->body_len = sizeof(*body);
		body->target = chan->remote;

		fill_msg_hdr(txbuf, chan->local, TIPC_CTRL_ADDR);
		err = vds_queue_txbuf(chan->vds, txbuf);
		if (err) {
			/* this should never happen */
			pr_err("%s: failed to queue tx buffer (%d)\n",
			       __func__, err);
		}
	} else {
		err = -ENOTCONN;
	}
	chan->state = TIPC_STALE;
	mutex_unlock(&chan->lock);

	if (err) {
		/* release buffer */
		tipc_chan_put_txbuf(chan, txbuf);
	}

	return err;
}
EXPORT_SYMBOL(tipc_chan_shutdown);

void tipc_chan_destroy(struct tipc_chan *chan)
{
	mutex_lock(&chan->lock);
	if (chan->vds) {
		vds_del_channel(chan->vds, chan);
		kref_put(&chan->vds->refcount, _free_vds);
		chan->vds = NULL;
	}
	mutex_unlock(&chan->lock);
	kref_put(&chan->refcount, _free_chan);
}
EXPORT_SYMBOL(tipc_chan_destroy);

/***************************************************************************/

struct tipc_dn_chan {
	int state;
	struct mutex lock; /* protects rx_msg_queue, idr and channel state */
	struct idr msg_idr;
	struct tipc_chan *chan;
	wait_queue_head_t readq;
	struct completion reply_comp;
	struct list_head rx_msg_queue;
};

static int dn_wait_for_reply(struct tipc_dn_chan *dn, int timeout)
{
	int ret;

	ret = wait_for_completion_interruptible_timeout(&dn->reply_comp,
					msecs_to_jiffies(timeout));
	if (ret < 0)
		return ret;

	mutex_lock(&dn->lock);
	if (!ret) {
		/* no reply from remote */
		dn->state = TIPC_STALE;
		ret = -ETIMEDOUT;
	} else {
		/* got reply */
		if (dn->state == TIPC_CONNECTED)
			ret = 0;
		else if (dn->state == TIPC_DISCONNECTED)
			if (!list_empty(&dn->rx_msg_queue))
				ret = 0;
			else
				ret = -ENOTCONN;
		else
			ret = -EIO;
	}
	mutex_unlock(&dn->lock);

	return ret;
}

struct tipc_msg_buf *dn_handle_msg(void *data, struct tipc_msg_buf *rxbuf)
{
	struct tipc_dn_chan *dn = data;
	struct tipc_msg_buf *newbuf = rxbuf;

	pr_devel("%s\n", __func__);
	mutex_lock(&dn->lock);
	if (dn->state == TIPC_CONNECTED) {
		/* get new buffer */
		newbuf = tipc_chan_get_rxbuf(dn->chan);
		if (newbuf) {
			/* queue an old buffer and return a new one */
			list_add_tail(&rxbuf->node, &dn->rx_msg_queue);
			wake_up_interruptible(&dn->readq);
		} else {
			/*
			 * return an old buffer effectively discarding
			 * incoming message
			 */
			pr_err("%s: discard incoming message\n", __func__);
			newbuf = rxbuf;
		}
	}
	mutex_unlock(&dn->lock);

	return newbuf;
}

static void dn_connected(struct tipc_dn_chan *dn)
{
	pr_devel("%s\n", __func__);
	mutex_lock(&dn->lock);
	dn->state = TIPC_CONNECTED;

	/* complete all pending  */
	complete(&dn->reply_comp);

	mutex_unlock(&dn->lock);
}

static void dn_disconnected(struct tipc_dn_chan *dn)
{
	pr_devel("%s\n", __func__);
	mutex_lock(&dn->lock);
	dn->state = TIPC_DISCONNECTED;

	/* complete all pending  */
	complete(&dn->reply_comp);

	/* wakeup all readers */
	wake_up_interruptible_all(&dn->readq);

	mutex_unlock(&dn->lock);
}

static void dn_shutdown(struct tipc_dn_chan *dn)
{
	pr_devel("%s\n", __func__);
	mutex_lock(&dn->lock);

	/* set state to STALE */
	dn->state = TIPC_STALE;

	/* complete all pending  */
	complete(&dn->reply_comp);

	/* wakeup all readers */
	wake_up_interruptible_all(&dn->readq);

	mutex_unlock(&dn->lock);
}

static void dn_handle_event(void *data, int event)
{
	struct tipc_dn_chan *dn = data;

	switch (event) {
	case TIPC_CHANNEL_SHUTDOWN:
		dn_shutdown(dn);
		break;

	case TIPC_CHANNEL_DISCONNECTED:
		dn_disconnected(dn);
		break;

	case TIPC_CHANNEL_CONNECTED:
		dn_connected(dn);
		break;

	default:
		pr_err("%s: unhandled event %d\n", __func__, event);
		break;
	}
}

static struct tipc_chan_ops _dn_ops = {
	.handle_msg = dn_handle_msg,
	.handle_event = dn_handle_event,
};

#define cdn_to_vds(cdn) container_of((cdn), struct tipc_virtio_dev, cdev_node)

static struct tipc_virtio_dev *_dn_lookup_vds(struct tipc_cdev_node *cdn)
{
	int ret;
	struct tipc_virtio_dev *vds = NULL;

	mutex_lock(&tipc_devices_lock);
	ret = idr_for_each(&tipc_devices, _match_data, cdn);
	if (ret) {
		vds = cdn_to_vds(cdn);
		kref_get(&vds->refcount);
	}
	mutex_unlock(&tipc_devices_lock);
	return vds;
}

int tipc_open(void *trusty_dev, struct tipc_dn_chan **dn_chan)
{
	int ret;
	struct tipc_virtio_dev *vds;
	struct tipc_dn_chan *dn;
	struct tipc_cdev_node *cdn = trusty_dev;

	pr_devel("%s\n", __func__);
	vds = _dn_lookup_vds(cdn);
	if (!vds) {
		ret = -ENOENT;
		goto err_vds_lookup;
	}

	dn = kzalloc(sizeof(*dn), GFP_KERNEL);
	if (!dn) {
		ret = -ENOMEM;
		goto err_alloc_chan;
	}

	mutex_init(&dn->lock);
	idr_init(&dn->msg_idr);
	init_waitqueue_head(&dn->readq);
	init_completion(&dn->reply_comp);
	INIT_LIST_HEAD(&dn->rx_msg_queue);

	dn->state = TIPC_DISCONNECTED;

	dn->chan = vds_create_channel(vds, &_dn_ops, dn);
	pr_devel("%s create chan local %d\n", __func__, dn->chan->local);
	if (IS_ERR(dn->chan)) {
		ret = PTR_ERR(dn->chan);
		goto err_create_chan;
	}

	*dn_chan = dn;
	kref_put(&vds->refcount, _free_vds);
	return 0;

err_create_chan:
	kfree(dn);
err_alloc_chan:
	kref_put(&vds->refcount, _free_vds);
err_vds_lookup:
	return ret;
}

int tipc_connect(struct tipc_dn_chan *dn, const char *srv_name)
{
	int err;
	char name[MAX_SRV_NAME_LEN];

	strncpy(name, srv_name, sizeof(name));
	name[sizeof(name)-1] = '\0';

	pr_devel("%s send connect request\n", __func__);
	/* send connect request */
	err = tipc_chan_connect(dn->chan, name);
	if (err)
		return err;

	/* and wait for reply */
	pr_devel("%s wait for reply\n", __func__);
	return dn_wait_for_reply(dn, REPLY_TIMEOUT);
}

static inline bool _got_rx(struct tipc_dn_chan *dn)
{
	if (dn->state != TIPC_CONNECTED)
		return true;

	if (!list_empty(&dn->rx_msg_queue))
		return true;

	return false;
}

ssize_t tipc_read_iter(struct tipc_dn_chan *dn, struct iov_iter *iter)
{
	ssize_t ret;
	size_t len;
	struct tipc_msg_buf *mb;

	pr_devel("%s(%x)\n", __func__, task_pid_nr(current));
	mutex_lock(&dn->lock);

	while (list_empty(&dn->rx_msg_queue)) {
		if (dn->state != TIPC_CONNECTED) {
			if (dn->state == TIPC_CONNECTING)
				ret = -ENOTCONN;
			else if (dn->state == TIPC_DISCONNECTED)
				ret = -ENOTCONN;
			else if (dn->state == TIPC_STALE)
				ret = -ESHUTDOWN;
			else
				ret = -EBADFD;
			goto out;
		}

		mutex_unlock(&dn->lock);

		/* this call may block */
		pr_devel("%s wait for event\n", __func__);
		if (wait_event_interruptible(dn->readq, _got_rx(dn)))
			return -ERESTARTSYS;

		mutex_lock(&dn->lock);
	}

	mb = list_first_entry(&dn->rx_msg_queue, struct tipc_msg_buf, node);

	len = mb_avail_data(mb);
	if (len > iov_iter_count(iter)) {
		pr_devel("len %zu > iov_iter %zu\n", len, iov_iter_count(iter));
		ret = -EMSGSIZE;
		goto out;
	}

	if (copy_to_iter(mb_get_data(mb, len), len, iter) != len) {
		ret = -EFAULT;
		goto out;
	}

	ret = len;
	list_del(&mb->node);
	tipc_chan_put_rxbuf(dn->chan, mb);

	pr_devel("%s(%x) done\n", __func__, task_pid_nr(current));
out:
	mutex_unlock(&dn->lock);
	return ret;
}

ssize_t tipc_write_iter(struct tipc_dn_chan *dn, struct iov_iter *iter)
{
	ssize_t ret;
	size_t len;
	long timeout = TXBUF_TIMEOUT;
	struct tipc_msg_buf *txbuf = NULL;

	pr_devel("%s(%x)\n", __func__, task_pid_nr(current));

	/* this call may block */
	txbuf = tipc_chan_get_txbuf_timeout(dn->chan, timeout);
	if (IS_ERR(txbuf))
		return PTR_ERR(txbuf);

	/* message length */
	len = iov_iter_count(iter);

	/* check available space */
	if (len > mb_avail_space(txbuf)) {
		ret = -EMSGSIZE;
		goto err_out;
	}

	/* copy in message data */
	if (copy_from_iter(mb_put_data(txbuf, len), len, iter) != len) {
		ret = -EFAULT;
		goto err_out;
	}

	pr_devel("%s queue message\n", __func__);
	/* queue message */
	ret = tipc_chan_queue_msg(dn->chan, txbuf);
	if (ret)
		goto err_out;

	pr_devel("%s(%x) done\n", __func__, task_pid_nr(current));
	return len;

err_out:
	tipc_chan_put_txbuf(dn->chan, txbuf);
	return ret;
}

ssize_t tipc_read(struct tipc_dn_chan *dn, void *buf, size_t buf_sz)
{
	struct kvec iov[2];
	struct iov_iter iter;
	struct mipstee_msg_hdr hdr = MIPSTEE_TIPC_HDR_INIT;

	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof(hdr);
	iov[1].iov_base = buf;
	iov[1].iov_len = buf_sz;

	// set up read from tipc chan writing to iov iter
	iov_iter_kvec(&iter, WRITE | ITER_KVEC, iov, 2,
			iov[0].iov_len + iov[1].iov_len);
	return tipc_read_iter(dn, &iter);
}

ssize_t tipc_write(struct tipc_dn_chan *dn, void *buf, size_t buf_sz)
{
	struct kvec iov[2];
	struct iov_iter iter;
	struct mipstee_msg_hdr hdr = MIPSTEE_TIPC_HDR_INIT;

	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof(hdr);
	iov[1].iov_base = buf;
	iov[1].iov_len = buf_sz;

	// set up write to tipc chan reading from iov iter
	iov_iter_kvec(&iter, READ | ITER_KVEC, iov, 2,
			iov[0].iov_len + iov[1].iov_len);
	return tipc_write_iter(dn, &iter);
}

static int tipc_alloc_tag(struct tipc_dn_chan *dn, struct tag_data *tag_data)
{
	int rc;

	mutex_lock(&dn->lock);
	rc = idr_alloc_cyclic(&dn->msg_idr, tag_data, 1, 0, GFP_KERNEL);
	mutex_unlock(&dn->lock);

	return rc;
}

static inline void tipc_remove_tag_locked(struct tipc_dn_chan *dn,
		struct tag_data *tag_data)
{
	idr_remove(&dn->msg_idr, tag_data->tag);
	tag_data->iter = NULL;
	tag_data->tag = 0;
	tag_data->r_ready = 0;
	tag_data->r_err = 0;
}

static void tipc_remove_tag(struct tipc_dn_chan *dn, struct tag_data *tag_data)
{
	mutex_lock(&dn->lock);
	tipc_remove_tag_locked(dn, tag_data);
	mutex_unlock(&dn->lock);
}

static ssize_t read_iter_locked(struct tipc_dn_chan *dn, struct iov_iter *iter)
{
	ssize_t ret = 0;
	size_t len;
	struct tipc_msg_buf *mb;

	mb = list_first_entry(&dn->rx_msg_queue, struct tipc_msg_buf, node);

	len = mb_avail_data(mb);
	if (len > iov_iter_count(iter)) {
		pr_devel("len %zu > iov_iter %zu\n", len, iov_iter_count(iter));
		ret = -EMSGSIZE;
		goto out;
	}

	if (copy_to_iter(mb_get_data(mb, len), len, iter) != len) {
		ret = -EFAULT;
		goto out;
	}

out:
	list_del(&mb->node);
	tipc_chan_put_rxbuf(dn->chan, mb);
	if (ret < 0)
		return ret;
	return len;
}

static int peek_at_tag_in_rx_msg_queue(struct tipc_dn_chan *dn)
{
	struct tipc_msg_buf *mb;
	struct mipstee_tipc_msg *ree_buf;

	mb = list_first_entry_or_null(&dn->rx_msg_queue, struct tipc_msg_buf, node);
	if (!mb)
		return 0;

	if (mb_avail_data(mb) < sizeof(struct mipstee_msg_hdr))
		return 0;

	ree_buf = mb_peek_data(mb, sizeof(struct mipstee_msg_hdr));
	if (ree_buf->hdr.magic != REE_MAGIC)
		return 0;

	return ree_buf->hdr.data_tag;
}

static bool got_rx_data(struct tipc_dn_chan *dn,
		struct tag_data *tag_data)
{
	if (!list_empty(&dn->rx_msg_queue))
		return true;

	if (tag_data->r_ready)
		return true;

	return false;
}

static inline bool _wait_rx(struct tipc_dn_chan *dn,
		struct tag_data *tag_data)
{
	if (dn->state != TIPC_CONNECTED)
		return true;

	if (got_rx_data(dn, tag_data))
		return true;

	return false;
}

static void read_tagged_locked(struct tipc_dn_chan *dn, struct tag_data *tag_data)
{
	struct tipc_msg_buf *mb;
	struct tag_data *rx_tag_data;
	int tag;
	ssize_t len;

	if (list_empty(&dn->rx_msg_queue))
		return;

	tag = peek_at_tag_in_rx_msg_queue(dn);

	rx_tag_data = idr_find(&dn->msg_idr, tag);
	if (!rx_tag_data) {
		// caller thread is gone, discard message
		mb = list_first_entry(&dn->rx_msg_queue, struct tipc_msg_buf,
				node);
		list_del(&mb->node);
		tipc_chan_put_rxbuf(dn->chan, mb);
		pr_info("%s(%x) read message dropped tag %i\n", __func__,
				task_pid_nr(current), tag);
	} else {
		// read reply for self or on behalf of another thread
		len = read_iter_locked(dn, rx_tag_data->iter);
		if (len < 0)
			rx_tag_data->r_err = len;
		rx_tag_data->r_ready = 1;
		pr_devel("%s(%x) read message (%s) tag %i\n", __func__,
				task_pid_nr(current), (rx_tag_data == tag_data)
				? "for self" : "for other", tag);
		// wake_up is required in order not to miss r_ready event
		if (rx_tag_data != tag_data)
			wake_up_interruptible(&dn->readq);
	}
}

static ssize_t tipc_read_tagged(struct tipc_dn_chan *dn, struct tag_data *tag_data)
{
	int ret = 0;
	ssize_t len = 0;

	pr_devel("%s(%x)\n", __func__, task_pid_nr(current));

	mutex_lock(&dn->lock);

loop:
	while (!got_rx_data(dn, tag_data)) {
		if (dn->state != TIPC_CONNECTED) {
			if (dn->state == TIPC_CONNECTING)
				ret = -ENOTCONN;
			else if (dn->state == TIPC_DISCONNECTED)
				ret = -ENOTCONN;
			else if (dn->state == TIPC_STALE)
				ret = -ESHUTDOWN;
			else
				ret = -EBADFD;
			goto out;
		}

		mutex_unlock(&dn->lock);

		pr_devel("%s(%x) wait for event\n", __func__,
				task_pid_nr(current));
		if (wait_event_interruptible(dn->readq,
				_wait_rx(dn, tag_data))) {
			tipc_remove_tag(dn, tag_data);
			return -ERESTARTSYS;
		}

		mutex_lock(&dn->lock);
	}

	if (tag_data->r_ready) {
		// check if reply is ready for this thread
		if (tag_data->r_err)
			ret = tag_data->r_err;
		else
			len = iov_iter_count(tag_data->iter);
		goto out;
	}

	read_tagged_locked(dn, tag_data);
	goto loop;

out:
	tipc_remove_tag_locked(dn, tag_data);
	mutex_unlock(&dn->lock);
	pr_devel("%s(%x) done\n", __func__, task_pid_nr(current));

	if (ret < 0)
		return ret;
	return len;
}

ssize_t tipc_call(struct tipc_dn_chan *dn, void *buf, size_t buf_sz)
{
	struct kvec iov_r[2];
	struct kvec iov_w[2];
	struct iov_iter iter_r;
	struct iov_iter iter_w;
	struct tag_data tag_data = { 0 };
	struct mipstee_msg_hdr hdr = MIPSTEE_TIPC_HDR_INIT;
	size_t len = 0;
	int rc;

	// writing to tipc channel will read from iter_r and
	// reading from tipc channel will write to iter_w
	iov_r[0].iov_base = &hdr;
	iov_r[0].iov_len = sizeof(hdr);
	iov_r[1].iov_base = buf;
	iov_r[1].iov_len = buf_sz;
	iov_iter_kvec(&iter_r, READ | ITER_KVEC, iov_r, 2,
			iov_r[0].iov_len + iov_r[1].iov_len);

	iov_w[0].iov_base = &hdr;
	iov_w[0].iov_len = sizeof(hdr);
	iov_w[1].iov_base = buf;
	iov_w[1].iov_len = buf_sz;
	iov_iter_kvec(&iter_w, WRITE | ITER_KVEC, iov_w, 2,
			iov_w[0].iov_len + iov_w[1].iov_len);

	rc = tipc_alloc_tag(dn, &tag_data);
	if (rc < 0) {
		pr_err("%s failed (%d) to get tag\n", __func__, rc);
		goto exit_no_cleanup;
	}

	// set up tag so reading from tipc channel will write to iter_w
	tag_data.iter = &iter_w;
	tag_data.tag = rc;
	hdr.data_tag = tag_data.tag;

	pr_devel("%s(%x) allocated message tag %i\n", __func__,
			task_pid_nr(current), tag_data.tag);

	len = tipc_write_iter(dn, &iter_r);
	if (len < 0) {
		rc = len;
		goto exit_cleanup;
	}

	// tipc_read_tagged will write to the iter it gets from tag_data
	len = tipc_read_tagged(dn, &tag_data);
	if (len < 0)
		rc = len;

	goto exit_no_cleanup;

exit_cleanup:
	tipc_remove_tag(dn, &tag_data);
exit_no_cleanup:
	if (rc < 0)
		return rc;
	return len;
}

int tipc_release(struct tipc_dn_chan *dn)
{
	pr_devel("%s shutdown\n", __func__);

	dn_shutdown(dn);

	/* free all pending buffers */
	_free_msg_buf_list(&dn->rx_msg_queue);

	/* shutdown channel  */
	tipc_chan_shutdown(dn->chan);

	/* and destroy it */
	tipc_chan_destroy(dn->chan);

	idr_destroy(&dn->msg_idr);

	kfree(dn);

	return 0;
}

/*****************************************************************************/

static void chan_trigger_event(struct tipc_chan *chan, int event)
{
	if (!event)
		return;

	chan->ops->handle_event(chan->ops_arg, event);
}

static void _cleanup_vq(struct virtqueue *vq)
{
	struct tipc_msg_buf *mb;

	while ((mb = virtqueue_detach_unused_buf(vq)) != NULL)
		_free_msg_buf(mb);
}

static int _create_cdev_node(struct device *parent,
			     struct tipc_cdev_node *cdn,
			     const char *name)
{
	int ret;

	(void)name;

	/* allocate minor */
	ret = idr_alloc(&tipc_devices, cdn, 0, MAX_DEVICES-1, GFP_KERNEL);
	if (ret < 0) {
		dev_dbg(parent, "%s: failed (%d) to get id\n",
			__func__, ret);
		return ret;
	}

	cdn->minor = ret;

	cdn->cdev_handle = mipstee_create_cdev_node(parent, cdn);
	if (IS_ERR(cdn->cdev_handle)) {
		ret = PTR_ERR(cdn->cdev_handle);
		dev_dbg(parent, "%s: create cdev node failed (%d)\n",
			__func__, ret);
		goto err_add_cdev;
	}

	return 0;

err_add_cdev:
	cdn->cdev_handle = NULL;
	idr_remove(&tipc_devices, cdn->minor);
	return ret;
}

static void create_cdev_node(struct tipc_virtio_dev *vds,
			     struct tipc_cdev_node *cdn)
{
	int err;

	mutex_lock(&tipc_devices_lock);

	if (!default_vdev) {
		kref_get(&vds->refcount);
		default_vdev = vds->vdev;
	}

	if (vds->cdev_name[0] && !cdn->cdev_handle) {
		kref_get(&vds->refcount);
		err = _create_cdev_node(&vds->vdev->dev, cdn, vds->cdev_name);
		if (err) {
			dev_err(&vds->vdev->dev,
				"failed (%d) to create cdev node\n", err);
			kref_put(&vds->refcount, _free_vds);
		}
	}
	mutex_unlock(&tipc_devices_lock);
}

static void destroy_cdev_node(struct tipc_virtio_dev *vds,
			      struct tipc_cdev_node *cdn)
{
	mutex_lock(&tipc_devices_lock);

	if (cdn->cdev_handle) {
		mipstee_delete_cdev_node(cdn->cdev_handle);
		idr_remove(&tipc_devices, cdn->minor);
		kref_put(&vds->refcount, _free_vds);
	}

	if (default_vdev == vds->vdev) {
		default_vdev = NULL;
		kref_put(&vds->refcount, _free_vds);
	}

	mutex_unlock(&tipc_devices_lock);
}

static void _go_online(struct tipc_virtio_dev *vds)
{
	mutex_lock(&vds->lock);
	if (vds->state == VDS_OFFLINE)
		vds->state = VDS_ONLINE;
	mutex_unlock(&vds->lock);

	create_cdev_node(vds, &vds->cdev_node);

	dev_info(&vds->vdev->dev, "is online\n");
}

static void _go_offline(struct tipc_virtio_dev *vds)
{
	struct tipc_chan *chan;

	/* change state to OFFLINE */
	mutex_lock(&vds->lock);
	if (vds->state != VDS_ONLINE) {
		mutex_unlock(&vds->lock);
		return;
	}
	vds->state = VDS_OFFLINE;
	mutex_unlock(&vds->lock);

	/* wakeup all waiters */
	wake_up_interruptible_all(&vds->sendq);

	/* shutdown all channels */
	while ((chan = vds_lookup_channel(vds, TIPC_ANY_ADDR))) {
		mutex_lock(&chan->lock);
		chan->state = TIPC_STALE;
		chan->remote = 0;
		chan_trigger_event(chan, TIPC_CHANNEL_SHUTDOWN);
		mutex_unlock(&chan->lock);
		kref_put(&chan->refcount, _free_chan);
	}

	/* shutdown device node */
	destroy_cdev_node(vds, &vds->cdev_node);

	dev_info(&vds->vdev->dev, "is offline\n");
}

static void _handle_conn_rsp(struct tipc_virtio_dev *vds,
			     struct tipc_conn_rsp_body *rsp, size_t len)
{
	struct tipc_chan *chan;

	if (sizeof(*rsp) != len) {
		dev_err(&vds->vdev->dev, "%s: Invalid response length %zd\n",
			__func__, len);
		return;
	}

	dev_dbg(&vds->vdev->dev,
		"%s: connection response: for addr 0x%x: "
		"status %d remote addr 0x%x\n",
		__func__, rsp->target, rsp->status, rsp->remote);

	/* Lookup channel */
	chan = vds_lookup_channel(vds, rsp->target);
	if (chan) {
		mutex_lock(&chan->lock);
		if (chan->state == TIPC_CONNECTING) {
			if (!rsp->status) {
				chan->state = TIPC_CONNECTED;
				chan->remote = rsp->remote;
				chan->max_msg_cnt = rsp->max_msg_cnt;
				chan->max_msg_size = rsp->max_msg_size;
				chan_trigger_event(chan,
						   TIPC_CHANNEL_CONNECTED);
			} else {
				chan->state = TIPC_DISCONNECTED;
				chan->remote = 0;
				chan_trigger_event(chan,
						   TIPC_CHANNEL_DISCONNECTED);
			}
		}
		mutex_unlock(&chan->lock);
		kref_put(&chan->refcount, _free_chan);
	}
}

static void _handle_disc_req(struct tipc_virtio_dev *vds,
			     struct tipc_disc_req_body *req, size_t len)
{
	struct tipc_chan *chan;

	if (sizeof(*req) != len) {
		dev_err(&vds->vdev->dev, "%s: Invalid request length %zd\n",
			__func__, len);
		return;
	}

	dev_dbg(&vds->vdev->dev, "%s: disconnect request: for addr 0x%x\n",
		__func__, req->target);

	chan = vds_lookup_channel(vds, req->target);
	if (chan) {
		mutex_lock(&chan->lock);
		if (chan->state == TIPC_CONNECTED ||
			chan->state == TIPC_CONNECTING) {
			chan->state = TIPC_DISCONNECTED;
			chan->remote = 0;
			chan_trigger_event(chan, TIPC_CHANNEL_DISCONNECTED);
		}
		mutex_unlock(&chan->lock);
		kref_put(&chan->refcount, _free_chan);
	}
}

static void _handle_ctrl_msg(struct tipc_virtio_dev *vds,
			     void *data, int len, u32 src)
{
	struct tipc_ctrl_msg *msg = data;

	if ((len < sizeof(*msg)) || (sizeof(*msg) + msg->body_len != len)) {
		dev_err(&vds->vdev->dev,
			"%s: Invalid message length ( %d vs. %d)\n",
			__func__, (int)(sizeof(*msg) + msg->body_len), len);
		return;
	}

	dev_dbg(&vds->vdev->dev,
		"%s: Incoming ctrl message: src 0x%x type %d len %d\n",
		__func__, src, msg->type, msg->body_len);

	switch (msg->type) {
	case TIPC_CTRL_MSGTYPE_GO_ONLINE:
		_go_online(vds);
	break;

	case TIPC_CTRL_MSGTYPE_GO_OFFLINE:
		_go_offline(vds);
	break;

	case TIPC_CTRL_MSGTYPE_CONN_RSP:
		_handle_conn_rsp(vds, (struct tipc_conn_rsp_body *)msg->body,
				 msg->body_len);
	break;

	case TIPC_CTRL_MSGTYPE_DISC_REQ:
		_handle_disc_req(vds, (struct tipc_disc_req_body *)msg->body,
				 msg->body_len);
	break;

	default:
		dev_warn(&vds->vdev->dev,
			 "%s: Unexpected message type: %d\n",
			 __func__, msg->type);
	}
}

static int _handle_rxbuf(struct tipc_virtio_dev *vds,
			 struct tipc_msg_buf *rxbuf, size_t rxlen)
{
	int err;
	struct scatterlist sg;
	struct tipc_msg_hdr *msg;
	struct device *dev = &vds->vdev->dev;

	/* message sanity check */
	if (rxlen > rxbuf->buf_sz) {
		dev_warn(dev, "inbound msg is too big: %zd\n", rxlen);
		goto drop_it;
	}

	if (rxlen < sizeof(*msg)) {
		dev_warn(dev, "inbound msg is too short: %zd\n", rxlen);
		goto drop_it;
	}

	/* reset buffer and put data  */
	mb_reset(rxbuf);
	mb_put_data(rxbuf, rxlen);

	/* get message header */
	msg = mb_get_data(rxbuf, sizeof(*msg));
	if (mb_avail_data(rxbuf) != msg->len) {
		dev_warn(dev, "inbound msg length mismatch: (%d vs. %d)\n",
			 (uint) mb_avail_data(rxbuf), (uint)msg->len);
		goto drop_it;
	}

	dev_dbg(dev, "From: %d, To: %d, Len: %d, Flags: 0x%x, Reserved: %d\n",
		msg->src, msg->dst, msg->len, msg->flags, msg->reserved);

	/* message directed to control endpoint is a special case */
	if (msg->dst == TIPC_CTRL_ADDR) {
		_handle_ctrl_msg(vds, msg->data, msg->len, msg->src);
	} else {
		struct tipc_chan *chan = NULL;
		/* Lookup channel */
		chan = vds_lookup_channel(vds, msg->dst);
		if (chan) {
			/* handle it */
			rxbuf = chan->ops->handle_msg(chan->ops_arg, rxbuf);
			BUG_ON(!rxbuf);
			kref_put(&chan->refcount, _free_chan);
		}
	}

drop_it:
	/* add the buffer back to the virtqueue */
	sg_init_one(&sg, rxbuf->buf_va, rxbuf->buf_sz);
	err = virtqueue_add_inbuf(vds->rxvq, &sg, 1, rxbuf, GFP_KERNEL);
	if (err < 0) {
		dev_err(dev, "failed to add a virtqueue buffer: %d\n", err);
		return err;
	}

	return 0;
}

static void rxvq_workfn(struct work_struct *work)
{
	struct tipc_virtio_dev *vds = container_of(work,
			struct tipc_virtio_dev, check_rxvq);
	struct virtqueue *rxvq = vds->rxvq;
	unsigned int len;
	struct tipc_msg_buf *mb;
	unsigned int msg_cnt = 0;

	while ((mb = virtqueue_get_buf(rxvq, &len)) != NULL) {
		if (_handle_rxbuf(vds, mb, len))
			break;
		msg_cnt++;
	}

	/* tell the other size that we added rx buffers */
	if (msg_cnt)
		virtqueue_kick(rxvq);
}

static void txvq_workfn(struct work_struct *work)
{
	struct tipc_virtio_dev *vds = container_of(work,
			struct tipc_virtio_dev, check_txvq);
	struct virtqueue *txvq = vds->txvq;
	unsigned int len;
	struct tipc_msg_buf *mb;
	bool need_wakeup = false;

	dev_dbg(&txvq->vdev->dev, "%s\n", __func__);

	/* detach all buffers */
	mutex_lock(&vds->lock);
	while ((mb = virtqueue_get_buf(txvq, &len)) != NULL)
		need_wakeup |= _put_txbuf_locked(vds, mb);
	mutex_unlock(&vds->lock);

	if (need_wakeup) {
		/* wake up potential senders waiting for a tx buffer */
		wake_up_interruptible_all(&vds->sendq);
	}
}

static void rxvq_cb(struct virtqueue *rxvq)
{
	struct tipc_virtio_dev *vds = rxvq->vdev->priv;
	queue_work(vds->check_wq, &vds->check_rxvq);
}

static void txvq_cb(struct virtqueue *txvq)
{
	struct tipc_virtio_dev *vds = txvq->vdev->priv;
	queue_work(vds->check_wq, &vds->check_txvq);
}

static int tipc_virtio_probe(struct virtio_device *vdev)
{
	int err, i;
	struct tipc_virtio_dev *vds;
	struct tipc_dev_config config;
	struct virtqueue *vqs[2];
	vq_callback_t *vq_cbs[] = {rxvq_cb, txvq_cb};
	const char *vq_names[] = { "rx", "tx" };

	dev_dbg(&vdev->dev, "%s:\n", __func__);

	vds = kzalloc(sizeof(*vds), GFP_KERNEL);
	if (!vds)
		return -ENOMEM;

	vds->vdev = vdev;

	mutex_init(&vds->lock);
	kref_init(&vds->refcount);
	init_waitqueue_head(&vds->sendq);
	INIT_LIST_HEAD(&vds->free_buf_list);
	idr_init(&vds->addr_idr);

	INIT_WORK(&vds->check_rxvq, rxvq_workfn);
	INIT_WORK(&vds->check_txvq, txvq_workfn);
	vds->check_wq = alloc_workqueue("trusty-check-wq", WQ_UNBOUND, 0);
	if (!vds->check_wq) {
		err = -ENODEV;
		dev_err(&vdev->dev, "Failed create trusty-check-wq\n");
		goto err_create_check_wq;
	}

	/* set default max message size and alignment */
	memset(&config, 0, sizeof(config));
	config.msg_buf_max_size  = DEFAULT_MSG_BUF_SIZE;
	config.msg_buf_alignment = DEFAULT_MSG_BUF_ALIGN;

	/* get configuration if present */
#if 1
	strncpy(config.dev_name, "trusty-ipc-dev0", sizeof(config.dev_name));
#else
	// XXX config space not implemented
	virtio_cread(vdev, struct tipc_dev_config, msg_buf_max_size, &config.msg_buf_max_size);
	virtio_cread(vdev, struct tipc_dev_config, msg_buf_alignment, &config.msg_buf_alignment);
	virtio_cread_bytes(vdev, offsetof(struct tipc_dev_config, dev_name),
		config.dev_name, sizeof(config.dev_name));
#endif

	/* copy dev name */
	strncpy(vds->cdev_name, config.dev_name, sizeof(vds->cdev_name));
	vds->cdev_name[sizeof(vds->cdev_name)-1] = '\0';

	/* find tx virtqueues (rx and tx and in this order) */
	err = vdev->config->find_vqs(vdev, 2, vqs, vq_cbs, vq_names);
	if (err)
		goto err_find_vqs;

	vds->rxvq = vqs[0];
	vds->txvq = vqs[1];

	/* save max buffer size and count */
	vds->msg_buf_max_sz = config.msg_buf_max_size;
	vds->msg_buf_max_cnt = virtqueue_get_vring_size(vds->txvq);

	/* set up the receive buffers */
	for (i = 0; i < virtqueue_get_vring_size(vds->rxvq); i++) {
		struct scatterlist sg;
		struct tipc_msg_buf *rxbuf;

		rxbuf = _alloc_msg_buf(vds->msg_buf_max_sz);
		if (!rxbuf) {
			dev_err(&vdev->dev, "failed to allocate rx buffer\n");
			err = -ENOMEM;
			goto err_free_rx_buffers;
		}

		sg_init_one(&sg, rxbuf->buf_va, rxbuf->buf_sz);
		err = virtqueue_add_inbuf(vds->rxvq, &sg, 1, rxbuf, GFP_KERNEL);
		WARN_ON(err); /* sanity check; this can't really happen */
	}

	vdev->priv = vds;
	vds->state = VDS_OFFLINE;

	dev_dbg(&vdev->dev, "%s: done\n", __func__);
	return 0;

err_free_rx_buffers:
	_cleanup_vq(vds->rxvq);
err_find_vqs:
	kref_put(&vds->refcount, _free_vds);
	destroy_workqueue(vds->check_wq);
err_create_check_wq:
	return err;
}

static void tipc_virtio_remove(struct virtio_device *vdev)
{
	struct tipc_virtio_dev *vds = vdev->priv;

	// TODO XXX untested: cancel_work_sync and destroy_workqueue
	/* wait until workqueues are done */
	cancel_work_sync(&vds->check_rxvq);
	cancel_work_sync(&vds->check_txvq);

	_go_offline(vds);

	destroy_workqueue(vds->check_wq);

	mutex_lock(&vds->lock);
	vds->state = VDS_DEAD;
	vds->vdev = NULL;
	mutex_unlock(&vds->lock);

	vdev->config->reset(vdev);

	idr_destroy(&vds->addr_idr);

	_cleanup_vq(vds->rxvq);
	_cleanup_vq(vds->txvq);
	_free_msg_buf_list(&vds->free_buf_list);

	vdev->config->del_vqs(vds->vdev);

	kref_put(&vds->refcount, _free_vds);
}

static struct virtio_device_id tipc_virtio_id_table[] = {
	{ VIRTIO_ID_L4TRUSTY_IPC, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {
	0,
};

static struct virtio_driver virtio_tipc_driver = {
	.feature_table	= features,
	.feature_table_size = ARRAY_SIZE(features),
	.driver.name	= KBUILD_MODNAME,
	.driver.owner	= THIS_MODULE,
	.id_table	= tipc_virtio_id_table,
	.probe		= tipc_virtio_probe,
	.remove		= tipc_virtio_remove,
};

static int __init tipc_init(void)
{
	int ret;
	dev_t dev;

	ret = alloc_chrdev_region(&dev, 0, MAX_DEVICES, KBUILD_MODNAME);
	if (ret) {
		pr_err("%s: alloc_chrdev_region failed: %d\n", __func__, ret);
		return ret;
	}

	tipc_major = MAJOR(dev);
	tipc_class = class_create(THIS_MODULE, KBUILD_MODNAME);
	if (IS_ERR(tipc_class)) {
		ret = PTR_ERR(tipc_class);
		pr_err("%s: class_create failed: %d\n", __func__, ret);
		goto err_class_create;
	}

	ret = register_virtio_driver(&virtio_tipc_driver);
	if (ret) {
		pr_err("failed to register virtio driver: %d\n", ret);
		goto err_register_virtio_drv;
	}

	return 0;

err_register_virtio_drv:
	class_destroy(tipc_class);

err_class_create:
	unregister_chrdev_region(dev, MAX_DEVICES);
	return ret;
}

static void __exit tipc_exit(void)
{
	unregister_virtio_driver(&virtio_tipc_driver);
	class_destroy(tipc_class);
	unregister_chrdev_region(MKDEV(tipc_major, 0), MAX_DEVICES);
}

/* We need to init this early */
subsys_initcall(tipc_init);
module_exit(tipc_exit);

MODULE_DEVICE_TABLE(tipc, tipc_virtio_id_table);
MODULE_DESCRIPTION("Trusty IPC driver");
MODULE_LICENSE("GPL v2");
