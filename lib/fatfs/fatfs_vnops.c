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
#define _GNU_SOURCE

#include <vfscore/vnode.h>
#include <vfscore/mount.h>
#include <dirent.h>
#include <uk/blkdev.h>
#include <vfscore/fs.h>
#include <vfscore/file.h>

#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "fatfs.h"

static __u64 inode_count = 1; /* inode 0 is reserved to root */

/*
 *  Time bits: 15-11 hours (0-23), 10-5 min, 4-0 sec /2
 *  Date bits: 15-9 year - 1980, 8-5 month, 4-0 day
 */
#define TEMP_DATE   0x3021
#define TEMP_TIME   0

#define fatfs_open	((vnop_open_t)vfscore_vop_nullop)
#define fatfs_close	((vnop_close_t)vfscore_vop_nullop)
static int fatfs_read   (struct vnode *, struct vfscore_file *, struct uio *, int);
static int fatfs_write	(struct vnode *, struct uio *, int);
#define fatfs_seek	((vnop_seek_t)vfscore_vop_nullop)
#define fatfs_ioctl	((vnop_ioctl_t)vfscore_vop_einval)
#define fatfs_fsync	((vnop_fsync_t)vfscore_vop_nullop)
static int fatfs_readdir(struct vnode *, struct vfscore_file *, struct dirent *);
static int fatfs_lookup	(struct vnode *, char *, struct vnode **);
static int fatfs_create	(struct vnode *, char *, mode_t);
static int fatfs_remove	(struct vnode *, struct vnode *, char *);
static int fatfs_rename	(struct vnode *, struct vnode *, char *, struct vnode *, struct vnode *, char *);
static int fatfs_mkdir	(struct vnode *, char *, mode_t);
static int fatfs_rmdir	(struct vnode *, struct vnode *, char *);
static int fatfs_getattr(struct vnode *, struct vattr *);
static int fatfs_setattr(struct vnode *, struct vattr *);
static int fatfs_inactive(struct vnode *);
static int fatfs_truncate(struct vnode *, off_t);
#define fatfs_link	((vnop_link_t)vfscore_vop_nullop)
#define fatfs_cache	((vnop_cache_t)vfscore_vop_nullop)
#define fatfs_fallocate	((vnop_fallocate_t)vfscore_vop_nullop)
#define fatfs_readlink	((vnop_readlink_t)vfscore_vop_nullop)
#define fatfs_symlink	((vnop_symlink_t)vfscore_vop_nullop)

/*
 * vnode operations
 */
struct vnops fatfs_vnops = {
	fatfs_open,		/* open */
	fatfs_close,		/* close */
	fatfs_read,		/* read */
	fatfs_write,		/* write */
	fatfs_seek,		/* seek */
	fatfs_ioctl,		/* ioctl */
	fatfs_fsync,		/* fsync */
	fatfs_readdir,		/* readdir */
	fatfs_lookup,		/* lookup */
	fatfs_create,		/* create */
	fatfs_remove,		/* remove */
	fatfs_rename,		/* remame */
	fatfs_mkdir,		/* mkdir */
	fatfs_rmdir,		/* rmdir */
	fatfs_getattr,		/* getattr */
	fatfs_setattr,		/* setattr */
	fatfs_inactive,		/* inactive */
	fatfs_truncate,		/* truncate */
	fatfs_link,             /* link */
	fatfs_cache,            /* cache */
	fatfs_fallocate,        /* fallocate */
	fatfs_readlink,         /* readlink */
	fatfs_symlink,          /* symlink */
};

/*
 * Read one cluster to buffer.
 */
static int
fat_read_cluster(struct fatfsmount *fmp, __u32 cluster)
{
	__u32 sec;

	sec = cl_to_sec(fmp, cluster);
	return uk_blkdev_sync_io(fmp->dev, 0, UK_BLKREQ_READ, sec, fmp->sec_per_cl, fmp->io_buf);
}

/*
 * Write one cluster from buffer.
 */
static int
fat_write_cluster(struct fatfsmount *fmp, __u32 cluster)
{
	__u32 sec;

	sec = cl_to_sec(fmp, cluster);
	return uk_blkdev_sync_io(fmp->dev, 0, UK_BLKREQ_WRITE, sec, fmp->sec_per_cl, fmp->io_buf);
}

/*
 * Lookup vnode for the specified file/directory.
 * The vnode data will be set properly.
 */
static int
fatfs_lookup(struct vnode *dvp, char *name, struct vnode **vpp)
{
	struct fatfsmount *fmp;
	struct fat_dirent *de;
	struct fatfs_node np;
	struct fatfs_node *vnp;
	struct vnode *vp;
	int error;

	*vpp = NULL;

	if (*name == '\0')
		return ENOENT;

	fmp = dvp->v_mount->m_data;
	uk_mutex_lock(&fmp->lock);

	DPRINTF(("fatfs_lookup: name=%s\n", name));

	error = fatfs_lookup_node(dvp, name, &np);
	if (error) {
		DPRINTF(("fatfs_lookup: failed!! name=%s\n", name));
		uk_mutex_unlock(&fmp->lock);
		return error;
	}

	if (vfscore_vget(dvp->v_mount, inode_count++, &vp)) {
		/* found in cache */
		*vpp = vp;
		uk_mutex_unlock(&fmp->lock);
		return 0;
	}

	vnp = malloc(sizeof(np));
	if (vp->v_data == NULL) {
		return ENOMEM;
	}
	vp->v_data = vnp;
	*vnp = np;

	de = &np.dirent;
	vp->v_type = IS_DIR(de) ? VDIR : VREG;
	fat_attr_to_mode(de->attr, &vp->v_mode);
	vp->v_mode = UK_ALLPERMS;
	vp->v_size = de->size;

	DPRINTF(("fatfs_lookup: cl=%d\n", de->cluster));
	uk_mutex_unlock(&fmp->lock);

	*vpp = vp;

	return 0;
}

static int
fatfs_read(struct vnode *vp, struct vfscore_file *fp, struct uio *uio,
	   int ioflag __unused)
{
	struct fatfsmount *fmp;
	size_t nr_read, nr_copy, buf_pos, size;
	int error;
	__u32 cl;
	off_t file_pos;
	struct iovec *iov;
	struct fatfs_node *np;
	void *buf;

	DPRINTF(("fatfs_read: vp=%x\n", vp));

	fmp = vp->v_mount->m_data;

	if (vp->v_type == VDIR)
		return EISDIR;
	if (vp->v_type != VREG)
		return EINVAL;

	/* Check if current file position is already end of file. */
	file_pos = uio->uio_offset;
	if (file_pos >= vp->v_size)
		return 0;

	/* find first non-empty iovec */
	iov = uio->uio_iov;
	while (!iov->iov_len) {
		uio->uio_iov++;
		uio->uio_iovcnt--;
	}
	buf = iov->iov_base;
	size = iov->iov_len;

	uk_mutex_lock(&fmp->lock);

	np = vp->v_data;

	/* Get the actual read size. */
	if ((size_t)(vp->v_size - file_pos) < size)
		size = vp->v_size - file_pos;

	/* Seek to the cluster for the file offset */
	error = fat_seek_cluster(fmp, np->dirent.cluster, file_pos, &cl);
	if (error)
		goto out;

	/* Read and copy data */
	nr_read = 0;
	buf_pos = file_pos % fmp->cluster_size;
	do {
		if (fat_read_cluster(fmp, cl)) {
			error = EIO;
			goto out;
		}

		nr_copy = fmp->cluster_size;
		if (buf_pos > 0)
			nr_copy -= buf_pos;
		if (buf_pos + size < fmp->cluster_size)
			nr_copy = size;
		memcpy(buf, fmp->io_buf + buf_pos, nr_copy);

		file_pos += (off_t)nr_copy;
		nr_read += nr_copy;
		size -= nr_copy;
		if (size <= 0)
			break;

		error = fat_next_cluster(fmp, cl, &cl);
		if (error)
			goto out;

		buf = (void *)((char*)buf + nr_copy);
		buf_pos = 0;
	} while (!IS_EOFCL(fmp, cl));

	uio->uio_resid -= (off_t)nr_read;
	uio->uio_offset += (off_t)nr_read;

	iov->iov_base = buf;
	iov->iov_len -= nr_read;

	error = 0;
 out:
	uk_mutex_unlock(&fmp->lock);
	return error;
}

static int
fatfs_write(struct vnode *vp, struct uio *uio, int ioflag __unused)
{
	struct fatfsmount *fmp;
	struct fatfs_node *np;
	struct fat_dirent *de;
	struct iovec *iov;
	size_t nr_copy, nr_write, buf_pos, i, cl_size;
	int error;
	__u32 file_pos, end_pos;
	__u32 cl;

	DPRINTF(("fatfs_write: vp=%x\n", vp));

	fmp = vp->v_mount->m_data;
	np = vp->v_data;

	if (vp->v_type == VDIR)
		return EISDIR;
	if (vp->v_type != VREG)
		return EINVAL;
	if (uio->uio_offset < 0)
		return EINVAL;
	if (uio->uio_offset >= LONG_MAX)
		return EFBIG;
	if (uio->uio_resid == 0)
		return 0;

	if (ioflag & IO_APPEND)
		uio->uio_offset = vp->v_size;

	/* find first non-empty iovec */
	iov = uio->uio_iov;
	while (!iov->iov_len) {
		uio->uio_iov++;
		uio->uio_iovcnt--;
	}

	uk_mutex_lock(&fmp->lock);

	/* Check if file position exceeds the end of file. */
	end_pos = vp->v_size;
	file_pos = uio->uio_offset;
	if (file_pos + iov->iov_len > end_pos) {

		/* Expand the file size before writing to it */
		end_pos = file_pos + iov->iov_len;
		cl = np->dirent.cluster;
		error = fat_expand_file(fmp, &cl, end_pos);
		if (error) {
			error = EIO;
			goto out;
		}
		np->dirent.cluster = cl;

		/* Update directory entry */
		de = &np->dirent;
		de->size = end_pos;
		error = fatfs_put_node(fmp, np);
		if (error)
			goto out;
		vp->v_size = (off_t)end_pos;
	}

	/* Seek to the cluster for the file offset */
	error = fat_seek_cluster(fmp, np->dirent.cluster, file_pos, &cl);
	if (error)
		goto out;

	buf_pos = file_pos % fmp->cluster_size;
	cl_size = iov->iov_len / fmp->cluster_size + 1;
	nr_write = 0;
	i = 0;
	do {
		/* First and last cluster must be read before write */
		if (i == 0 || i == cl_size) {
			if (fat_read_cluster(fmp, cl)) {
				error = EIO;
				goto out;
			}
		}
		nr_copy = fmp->cluster_size;
		if (buf_pos > 0)
			nr_copy -= buf_pos;
		if (buf_pos + iov->iov_len < fmp->cluster_size)
			nr_copy = iov->iov_len;
		memcpy(fmp->io_buf + buf_pos, iov->iov_base, nr_copy);

		if (fat_write_cluster(fmp, cl)) {
			error = EIO;
			goto out;
		}
		file_pos += nr_copy;
		nr_write += nr_copy;
		iov->iov_len -= nr_copy;
		if (iov->iov_len <= 0)
			break;

		error = fat_next_cluster(fmp, cl, &cl);
		if (error)
			goto out;

		iov->iov_base = (void *)((char*)iov->iov_base + nr_copy);
		buf_pos = 0;
		i++;
	} while (!IS_EOFCL(fmp, cl));

	uio->uio_resid -= (off_t)nr_write;
	uio->uio_offset += (off_t)nr_write;

	/*
	 * XXX: Todo!
	 *    de.time = ?
	 *    de.date = ?
	 *    if (dirent_set(fp, &de))
	 *        return EIO;
	 */
	error = 0;
 out:
	uk_mutex_unlock(&fmp->lock);
	return error;
}

static int
fatfs_readdir(struct vnode *vp, struct vfscore_file *fp, struct dirent *dir)
{
	struct fatfsmount *fmp;
	struct fatfs_node np;
	struct fat_dirent *de;
	int error;

	fmp = vp->v_mount->m_data;
	uk_mutex_lock(&fmp->lock);

	error = fatfs_get_node(vp, (int)fp->f_offset, &np);
	if (error)
		goto out;
	de = &np.dirent;
	fat_restore_name((char *)&de->name, dir->d_name);

	if (de->attr & FA_SUBDIR)
		dir->d_type = DT_DIR;
	else if (de->attr & FA_DEVICE)
		dir->d_type = DT_BLK;
	else
		dir->d_type = DT_REG;

	dir->d_fileno = fp->f_offset;

	fp->f_offset++;
	error = 0;
 out:
	uk_mutex_unlock(&fmp->lock);
	return error;
}

/*
 * Create empty file.
 */
static int
fatfs_create(struct vnode *dvp, char *name, mode_t mode)
{
	struct fatfsmount *fmp;
	struct fatfs_node np;
	struct fat_dirent *de;
	__u32 cl;
	int error;

	DPRINTF(("fatfs_create: %s\n", name));

	if (!S_ISREG(mode))
		return EINVAL;

	if (!fat_valid_name(name))
		return EINVAL;

	fmp = dvp->v_mount->m_data;
	uk_mutex_lock(&fmp->lock);

	/* Allocate free cluster for new file. */
	error = fat_alloc_cluster(fmp, 0, &cl);
	if (error)
		goto out;

	de = &np.dirent;
	memset(de, 0, sizeof(struct fat_dirent));
	fat_convert_name(name, (char *)de->name);
	de->cluster = cl;
	de->time = TEMP_TIME;
	de->date = TEMP_DATE;
	fat_mode_to_attr(mode, &de->attr);
	error = fatfs_add_node(dvp, &np);
	if (error)
		goto out;
	error = fat_set_cluster(fmp, cl, fmp->fat_eof);
 out:
	uk_mutex_unlock(&fmp->lock);
	return error;
}

static int
fatfs_remove(struct vnode *dvp, struct vnode *vp __unused, char *name)
{
	struct fatfsmount *fmp;
	struct fatfs_node np;
	struct fat_dirent *de;
	int error;

	if (*name == '\0')
		return ENOENT;

	fmp = dvp->v_mount->m_data;
	uk_mutex_lock(&fmp->lock);

	error = fatfs_lookup_node(dvp, name, &np);
	if (error)
		goto out;
	de = &np.dirent;
	if (IS_DIR(de)) {
		error = EISDIR;
		goto out;
	}
	if (!IS_FILE(de)) {
		error = EPERM;
		goto out;
	}

	/* Remove clusters */
	error = fat_free_clusters(fmp, de->cluster);
	if (error)
		goto out;

	/* remove directory */
	de->name[0] = 0xe5;
	error = fatfs_put_node(fmp, &np);
 out:
	uk_mutex_unlock(&fmp->lock);
	return error;
}

static int
fatfs_rename(struct vnode *dvp1, struct vnode *vp1, char *name1,
	     struct vnode *dvp2, struct vnode *vp2, char *name2)
{
	struct fatfsmount *fmp;
	struct fatfs_node np1;
	struct fat_dirent *de1, *de2;
	int error;

	fmp = dvp1->v_mount->m_data;
	uk_mutex_lock(&fmp->lock);

	error = fatfs_lookup_node(dvp1, name1, &np1);
	if (error)
		goto out;
	de1 = &np1.dirent;

	if (IS_FILE(de1)) {
		/* Remove destination file, first */
		error = fatfs_remove(dvp2, vp1, name2);
		if (error == EIO)
			goto out;

		/* Change file name of directory entry */
		fat_convert_name(name2, (char *)de1->name);

		/* Same directory ? */
		if (dvp1 == dvp2) {
			/* Change the name of existing file */
			error = fatfs_put_node(fmp, &np1);
			if (error)
				goto out;
		} else {
			/* Create new directory entry */
			error = fatfs_add_node(dvp2, &np1);
			if (error)
				goto out;

			/* Remove souce file */
			error = fatfs_remove(dvp1, vp2, name1);
			if (error)
				goto out;
		}
	} else {

		/* remove destination directory */
		error = fatfs_rmdir(dvp2, NULL, name2);
		if (error == EIO)
			goto out;

		/* Change file name of directory entry */
		fat_convert_name(name2, (char *)de1->name);

		/* Same directory ? */
		if (dvp1 == dvp2) {
			/* Change the name of existing directory */
			error = fatfs_put_node(fmp, &np1);
			if (error)
				goto out;
		} else {
			/* Create new directory entry */
			error = fatfs_add_node(dvp2, &np1);
			if (error)
				goto out;

			/* Update "." and ".." for renamed directory */
			if (fat_read_cluster(fmp, de1->cluster)) {
				error = EIO;
				goto out;
			}

			de2 = (struct fat_dirent *)fmp->io_buf;
			de2->cluster = de1->cluster;
			de2->time = TEMP_TIME;
			de2->date = TEMP_DATE;
			de2++;
			de2->cluster = ((struct fatfs_node *)dvp2->v_data)->dirent.cluster;
			de2->time = TEMP_TIME;
			de2->date = TEMP_DATE;

			if (fat_write_cluster(fmp, de1->cluster)) {
				error = EIO;
				goto out;
			}

			/* Remove souce directory */
			error = fatfs_rmdir(dvp1, NULL, name1);
			if (error)
				goto out;
		}
	}
 out:
	uk_mutex_unlock(&fmp->lock);
	return error;
}

static int
fatfs_mkdir(struct vnode *dvp, char *name, mode_t mode)
{
	struct fatfsmount *fmp;
	struct fatfs_node np;
	struct fat_dirent *de;
	__u32 cl;
	int error;

	if (!S_ISDIR(mode))
		return EINVAL;

	if (!fat_valid_name(name))
		return ENOTDIR;

	fmp = dvp->v_mount->m_data;
	uk_mutex_lock(&fmp->lock);

	/* Allocate free cluster for directory data */
	error = fat_alloc_cluster(fmp, 0, &cl);
	if (error)
		goto out;

	memset(&np, 0, sizeof(struct fatfs_node));
	de = &np.dirent;
	fat_convert_name(name, (char *)&de->name);
	de->cluster = cl;
	de->time = TEMP_TIME;
	de->date = TEMP_DATE;
	fat_mode_to_attr(mode, &de->attr);
	error = fatfs_add_node(dvp, &np);
	if (error)
		goto out;

	/* Initialize "." and ".." for new directory */
	memset(fmp->io_buf, 0, fmp->cluster_size);

	de = (struct fat_dirent *)fmp->io_buf;
	memcpy(de->name, ".          ", 11);
	de->attr = FA_SUBDIR;
	de->cluster = cl;
	de->time = TEMP_TIME;
	de->date = TEMP_DATE;
	de++;
	memcpy(de->name, "..         ", 11);
	de->attr = FA_SUBDIR;
	de->cluster = ((struct fatfs_node *)dvp->v_data)->dirent.cluster;
	de->time = TEMP_TIME;
	de->date = TEMP_DATE;

	if (fat_write_cluster(fmp, cl)) {
		error = EIO;
		goto out;
	}
	/* Add eof */
	error = fat_set_cluster(fmp, cl, fmp->fat_eof);
 out:
	uk_mutex_unlock(&fmp->lock);
	return error;
}

/*
 * remove can be done only with empty directory
 */
static int
fatfs_rmdir(struct vnode *dvp, struct vnode *vp __unused, char *name)
{
	struct fatfsmount *fmp;
	struct fatfs_node np;
	struct fat_dirent *de;
	int error;

	if (*name == '\0')
		return ENOENT;

	fmp = dvp->v_mount->m_data;
	uk_mutex_lock(&fmp->lock);

	error = fatfs_lookup_node(dvp, name, &np);
	if (error)
		goto out;

	de = &np.dirent;
	if (!IS_DIR(de)) {
		error = ENOTDIR;
		goto out;
	}

	/* Remove clusters */
	error = fat_free_clusters(fmp, de->cluster);
	if (error)
		goto out;

	/* remove directory */
	de->name[0] = 0xe5;

	error = fatfs_put_node(fmp, &np);
 out:
	uk_mutex_unlock(&fmp->lock);
	return error;
}

static int
fatfs_getattr(struct vnode *vp, struct vattr *vap)
{
	vap->va_type = vp->v_type;
	vap->va_mode = vp->v_mode;
	vap->va_nodeid = vp->v_ino;
	vap->va_size = vp->v_size;
	return 0;
}

static int
fatfs_setattr(struct vnode *vp __unused, struct vattr *vap __unused)
{
	/* XXX */
	return 0;
}


static int
fatfs_inactive(struct vnode *vp)
{

	free(vp->v_data);
	return 0;
}

static int
fatfs_truncate(struct vnode *vp, off_t length)
{
	struct fatfsmount *fmp;
	struct fatfs_node *np;
	struct fat_dirent *de;
	int error;
	__u32 cl;

	fmp = vp->v_mount->m_data;
	uk_mutex_lock(&fmp->lock);

	np = vp->v_data;
	de = &np->dirent;

	if (length == 0) {
		/* Remove clusters */
		error = fat_free_clusters(fmp, de->cluster);
		if (error)
			goto out;
	} else if (length > vp->v_size) {
		cl = de->cluster;
		error = fat_expand_file(fmp, &cl, length);
		if (error) {
			error = EIO;
			goto out;
		}
		de->cluster = cl;
	}

	/* Update directory entry */
	de->size = length;
	error = fatfs_put_node(fmp, np);
	if (error)
		goto out;
	vp->v_size = length;
 out:
	uk_mutex_unlock(&fmp->lock);
	return error;
}
