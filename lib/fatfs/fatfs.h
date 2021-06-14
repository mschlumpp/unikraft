/*
 * Copyright (c) 2005-2007, Kohsuke Ohtani
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

#ifndef _FATFS_H
#define _FATFS_H

#include <vfscore/vnode.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <stdint.h>

#define DPRINTF(a)	uk_pr_debug a

#ifndef CONFIG_HAVE_SCHED
#define uk_mutex_init(m)		do {} while (0)
#define uk_mutex_destroy(m)		do {} while (0)
#define uk_mutex_unlock(m)		do {} while (0)
#define uk_mutex_unlock(m)		do {} while (0)
#define uk_mutex_trylock(m)		do {} while (0)
#endif


#define SEC_SIZE	512		/* sector size */
#define SEC_INVAL	0xffffffff	/* invalid sector */

/*
 * Pre-defined cluster number
 */
#define CL_ROOT		0		/* cluster 0 means the root directory */
#define CL_FREE		0		/* cluster 0 also means the free cluster */
#define CL_FIRST	2		/* first legal cluster */
#define CL_LAST		0xfffffff5	/* last legal cluster */
#define CL_EOF		0xffffffff	/* EOF cluster */

#define EOF_MASK	0xfffffff8	/* mask of eof */

#define FAT12_MASK	0x00000fff
#define FAT16_MASK	0x0000ffff

#if defined(__SUNPRO_C)
#pragma pack(1)
#endif

/*
 * BIOS parameter block
 */
struct fat_bpb {
	__u16	jmp_instruction;
	__u8	nop_instruction;
	__u8	oem_id[8];
	__u16	bytes_per_sector;
	__u8	sectors_per_cluster;
	__u16	reserved_sectors;
	__u8	num_of_fats;
	__u16	root_entries;
	__u16	total_sectors;
	__u8	media_descriptor;
	__u16	sectors_per_fat;
	__u16	sectors_per_track;
	__u16	heads;
	__u32	hidden_sectors;
	__u32	big_total_sectors;
	__u8	physical_drive;
	__u8	reserved;
	__u8	ext_boot_signature;
	__u32	serial_no;
	__u8	volume_id[11];
	__u8	file_sys_id[8];
} __packed;

/*
 * FAT directory entry
 */
struct fat_dirent {
	__u8	name[11];
	__u8	attr;
	__u8	reserve[10];
	__u16	time;
	__u16	date;
	__u16	cluster;
	__u32	size;
} __packed;

#if defined(__SUNPRO_C)
#pragma pack()
#endif

#define SLOT_EMPTY	0x00
#define SLOT_DELETED	0xe5

#define DIR_PER_SEC     (SEC_SIZE / (int)sizeof(struct fat_dirent))

/*
 * FAT attribute for attr
 */
#define FA_RDONLY	0x01
#define FA_HIDDEN	0x02
#define FA_SYSTEM	0x04
#define FA_VOLID	0x08
#define FA_SUBDIR	0x10
#define FA_ARCH		0x20
#define FA_DEVICE	0x40

#define IS_DIR(de)	(((de)->attr) & FA_SUBDIR)
#define IS_VOL(de)	(((de)->attr) & FA_VOLID)
#define IS_FILE(de)	(!IS_DIR(de) && !IS_VOL(de))

#define IS_DELETED(de)  ((de)->name[0] == 0xe5)
#define IS_EMPTY(de)    ((de)->name[0] == 0)

/*
 * Mount data
 */
struct fatfsmount {
	int			fat_type;	/* 12 or 16 */
	__u32			root_start;	/* start sector for root directory */
	__u32			fat_start;	/* start sector for fat entries */
	__u32			data_start;	/* start sector for data */
	__u32			fat_eof;	/* id of end cluster */
	__u32			sec_per_cl;	/* sectors per cluster */
	__u32			cluster_size;	/* cluster size */
	__u32			last_cluster;	/* last cluser */
	__u32			fat_mask;	/* mask for cluster# */
	__u32			free_scan;	/* start cluster# to free search */
	struct vnode		*root_vnode;	/* vnode for root */
	char			*io_buf;	/* local data buffer */
	char			*fat_buf;	/* buffer for fat entry */
	char			*dir_buf;	/* buffer for directory entry */
	struct uk_blkdev	*dev;		/* mounted device */
#ifdef CONFIG_LIBUKSCHED
	struct uk_mutex		lock;		/* file system lock */
#endif
};

#define FAT12(fat)	((fat)->fat_type == 12)
#define FAT16(fat)	((fat)->fat_type == 16)

#define IS_EOFCL(fat, cl) \
	(((cl) & EOF_MASK) == ((fat)->fat_mask & EOF_MASK))

/*
 * File/directory node
 */
struct fatfs_node {
	struct fat_dirent dirent; 	/* copy of directory entry */
	__u32	sector;			/* sector# for directory entry */
	__u32	offset;			/* offset of directory entry in sector */
};

extern struct vnops fatfs_vnops;

/* Macro to convert cluster# to logical sector# */
#define cl_to_sec(fat, cl) \
            (fat->data_start + (cl - 2) * fat->sec_per_cl)

int	 fat_next_cluster(struct fatfsmount *fmp, __u32 cl, __u32 *next);
int	 fat_set_cluster(struct fatfsmount *fmp, __u32 cl, __u32 next);
int	 fat_alloc_cluster(struct fatfsmount *fmp, __u32 scan_start, __u32 *free);
int	 fat_free_clusters(struct fatfsmount *fmp, __u32 start);
int	 fat_seek_cluster(struct fatfsmount *fmp, __u32 start, __u32 offset,
			    __u32 *cl);
int	 fat_expand_file(struct fatfsmount *fmp, __u32 *cl, __u32 size);
int	 fat_expand_dir(struct fatfsmount *fmp, __u32 cl, __u32 *new_cl);

void	 fat_convert_name(char *org, char *name);
void	 fat_restore_name(char *org, char *name);
int	 fat_valid_name(char *name);
int	 fat_compare_name(char *n1, char *n2);
void	 fat_mode_to_attr(mode_t mode, unsigned char *attr);
void	 fat_attr_to_mode(unsigned char attr, mode_t *mode);

int	 fatfs_lookup_node(struct vnode *dvp, char *name, struct fatfs_node *node);
int	 fatfs_get_node(struct vnode *dvp, int index, struct fatfs_node *node);
int	 fatfs_put_node(struct fatfsmount *fmp, struct fatfs_node *node);
int	 fatfs_add_node(struct vnode *dvp, struct fatfs_node *node);

#endif /* !_FATFS_H */
