/*
 * Copyright (c) 2005-2008, Kohsuke Ohtani
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <vfscore/vnode.h>
#include <vfscore/mount.h>

#include <uk/blkdev.h>

#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "fatfs.h"

static int fatfs_mount	(struct mount *mp, const char *dev, int flags, const void *data);
static int fatfs_unmount(struct mount *mp, int flags);
#define fatfs_sync	((vfsop_sync_t)vfscore_nullop)
static int fatfs_vget	(struct mount *mp, struct vnode* vp);
#define fatfs_statfs	((vfsop_statfs_t)vfscore_nullop)

/*
 * File system operations
 */
struct vfsops fatfs_vfsops = {
	fatfs_mount,		/* mount */
	fatfs_unmount,		/* unmount */
	fatfs_sync,		/* sync */
	fatfs_vget,		/* vget */
	fatfs_statfs,		/* statfs */
	&fatfs_vnops,		/* vnops */
};

static struct vfscore_fs_type fs_fatfs = {
    .vs_name = "fatfs",
    .vs_init = NULL,
    .vs_op = &fatfs_vfsops,
};

UK_FS_REGISTER(fs_fatfs);

/*
 * Read BIOS parameter block.
 * Return 0 on sucess.
 */
static int
fat_read_bpb(struct fatfsmount *fmp)
{
	struct fat_bpb *bpb;
	int error;

	bpb = malloc(SEC_SIZE);
	if (bpb == NULL)
		return ENOMEM;

	/* Read boot sector (block:0) */
	error = uk_blkdev_sync_io(fmp->dev, 0, UK_BLKREQ_READ, 0, 1, bpb);
	if (error) {
		free(bpb);
		return error;
	}
	if (bpb->bytes_per_sector != SEC_SIZE) {
		DPRINTF(("fatfs: invalid sector size\n"));
		free(bpb);
		return EINVAL;
	}

	/* Build FAT mount data */
	fmp->fat_start = bpb->hidden_sectors + bpb->reserved_sectors;
	fmp->root_start = fmp->fat_start +
		(bpb->num_of_fats * bpb->sectors_per_fat);
	fmp->data_start =
		fmp->root_start + (bpb->root_entries / DIR_PER_SEC);
	fmp->sec_per_cl = bpb->sectors_per_cluster;
	fmp->cluster_size = bpb->sectors_per_cluster * SEC_SIZE;
	fmp->last_cluster = (bpb->total_sectors - fmp->data_start) /
		bpb->sectors_per_cluster + CL_FIRST;
	fmp->free_scan = CL_FIRST;

	if (!strncmp((const char *)bpb->file_sys_id, "FAT12   ", 8)) {
		fmp->fat_type = 12;
		fmp->fat_mask = FAT12_MASK;
		fmp->fat_eof = CL_EOF & FAT12_MASK;
	} else if (!strncmp((const char *)bpb->file_sys_id, "FAT16   ", 8)) {
		fmp->fat_type = 16;
		fmp->fat_mask = FAT16_MASK;
		fmp->fat_eof = CL_EOF & FAT16_MASK;
	} else {
		/* FAT32 is not supported now! */
		DPRINTF(("fatfs: invalid FAT type\n"));
		free(bpb);
		return EINVAL;
	}
	free(bpb);

	DPRINTF(("----- FAT info -----\n"));
	DPRINTF(("drive:%x\n", (int)bpb->physical_drive));
	DPRINTF(("total_sectors:%d\n", (int)bpb->total_sectors));
	DPRINTF(("heads       :%d\n", (int)bpb->heads));
	DPRINTF(("serial      :%x\n", (int)bpb->serial_no));
	DPRINTF(("cluster size:%u sectors\n", (int)fmp->sec_per_cl));
	DPRINTF(("fat_type    :FAT%u\n", (int)fmp->fat_type));
	DPRINTF(("fat_eof     :0x%x\n\n", (int)fmp->fat_eof));
	return 0;
}

static void fatfs_blkdev_callback(struct uk_blkdev *dev,
				 uint16_t queue_id, void *argp __unused) {
	uk_blkdev_queue_finish_reqs(dev, queue_id);
}

static int fatfs_open_blkdev(const char *dev, struct uk_blkdev **blkdev_out) {
	__u32 dev_idx;
	struct uk_blkdev *blkdev;
	int error;
	struct uk_blkdev_conf blkdev_conf = {0};
	struct uk_blkdev_queue_info blkdev_queue_info = {0};
	struct uk_blkdev_queue_conf blkdev_queue_conf = {0};

	if (dev == NULL || strncmp(dev, "bd", 2) != 0) {
		return EINVAL;
	}

	dev_idx = strtoul(dev + 2, NULL, 10);
	blkdev = uk_blkdev_get(dev_idx);
	if (blkdev == NULL) {
		return ENOENT;
	}

	blkdev_conf.nb_queues = 1;
	error = uk_blkdev_configure(blkdev, &blkdev_conf);
	if (error) {
		return error;
	}

	error = uk_blkdev_queue_get_info(blkdev, 0, &blkdev_queue_info);
	if (error) {
		goto queue_conf_err;
	}

	blkdev_queue_conf.a = uk_alloc_get_default();
	blkdev_queue_conf.callback = fatfs_blkdev_callback;
	error = uk_blkdev_queue_configure(blkdev, 0, blkdev_queue_info.nb_min,
					  &blkdev_queue_conf);
	if (error) {
		goto queue_conf_err;
	}

	error = uk_blkdev_start(blkdev);
	if (error) {
		goto blkdev_start_err;
	}

	if (uk_blkdev_ssize(blkdev) != SEC_SIZE) {
		error = EINVAL;
		goto property_err;
	}

	error = uk_blkdev_queue_intr_enable(blkdev, 0);
	if (error) {
		goto property_err;
	}

	*blkdev_out = blkdev;
	return 0;

property_err:
	uk_blkdev_stop(blkdev);
blkdev_start_err:
	uk_blkdev_queue_unconfigure(blkdev, 0);
queue_conf_err:
	uk_blkdev_unconfigure(blkdev);

	return error;
}

static int fatfs_close_blkdev(struct uk_blkdev *blkdev) {
	int error;

	error = uk_blkdev_stop(blkdev);
	if (error) {
		return error;
	}

	error = uk_blkdev_queue_unconfigure(blkdev, 0);
	if (error) {
		return error;
	}

	error = uk_blkdev_unconfigure(blkdev);
	if (error) {
		return error;
	}

	return 0;
}

/*
 * Mount file system.
 */
static int
fatfs_mount(struct mount *mp, const char *dev, int flags __unused,
	    const void *data __unused)
{
	struct fatfsmount *fmp;
	struct fatfs_node *vnp;
	struct vnode *vp;
	int error = 0;

	DPRINTF(("fatfs_mount device=%s\n", dev));

	fmp = malloc(sizeof(struct fatfsmount));
	if (fmp == NULL)
		return ENOMEM;

	error = fatfs_open_blkdev(dev, &fmp->dev);
	if (error) {
		return error;
	}

	if (fat_read_bpb(fmp) != 0)
		goto err1;

	error = ENOMEM;
	fmp->io_buf = malloc(fmp->sec_per_cl * SEC_SIZE);
	if (fmp->io_buf == NULL)
		goto err1;

	fmp->fat_buf = malloc(SEC_SIZE * 2);
	if (fmp->fat_buf == NULL)
		goto err2;

	fmp->dir_buf = malloc(SEC_SIZE);
	if (fmp->dir_buf == NULL)
		goto err3;

	uk_mutex_init(&fmp->lock);
	mp->m_data = fmp;
	vp = mp->m_root->d_vnode;
	vnp = malloc(sizeof(struct fatfs_node));
	vnp->dirent.cluster = CL_ROOT;
	vp->v_data = vnp;
	return 0;
 err3:
	free(fmp->fat_buf);
 err2:
	free(fmp->io_buf);
 err1:
	fatfs_close_blkdev(fmp->dev);
	free(fmp);
	return error;
}

/*
 * Unmount the file system.
 */
static int
fatfs_unmount(struct mount *mp, int flags __unused)
{
	struct fatfsmount *fmp;

	// FIXME: free dentries?
	fmp = mp->m_data;
	fatfs_close_blkdev(fmp->dev);
	free(fmp->dir_buf);
	free(fmp->fat_buf);
	free(fmp->io_buf);
	free(fmp);
	return 0;
}

/*
 * Prepare the FAT specific node and fill the vnode.
 */
static int
fatfs_vget(struct mount *mp __unused, struct vnode *vp)
{
	struct fatfs_node *np;

	np = malloc(sizeof(struct fatfs_node));
	if (np == NULL)
		return ENOMEM;
	vp->v_data = np;
	return 0;
}

