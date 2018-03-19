/*
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

#ifndef TIPC_PRIVATE_H
#define TIPC_PRIVATE_H

struct tipc_cdev_node;
struct tipc_dn_chan;

int tipc_open(void *trusty_dev, struct tipc_dn_chan **dn_chan);
int tipc_connect(struct tipc_dn_chan *dn, const char *srv_name);
ssize_t tipc_read_iter(struct tipc_dn_chan *dn, struct iov_iter *iter);
ssize_t tipc_write_iter(struct tipc_dn_chan *dn, struct iov_iter *iter);
int tipc_release(struct tipc_dn_chan *dn);

#endif /* TIPC_PRIVATE_H */
