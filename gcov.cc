// SPDX-License-Identifier: GPL-2.0
/*
 *  This code provides functions to handle gcc's profiling data format
 *  introduced with gcc 4.7.
 *
 *  This file is based heavily on gcc_3_4.c file.
 *
 *  For a better understanding, refer to gcc source:
 *  gcc/gcov-io.h
 *  libgcc/libgcov.c
 *
 *  Uses gcc-internal data definitions.
 */

#include <linux/errno.h>
#include <linux/string.h>
#include "gcov.h"
/**
 * gcov_info_filename - return info filename
 * @info: profiling data set
 */
const char *gcov_info_filename(struct gcov_info *info)
{
	return info->filename;
}

/**
 * gcov_info_version - return info version
 * @info: profiling data set
 */
unsigned int gcov_info_version(struct gcov_info *info)
{
	return info->version;
}

/**
 * gcov_info_next - return next profiling data set
 * @info: profiling data set
 *
 * Returns next gcov_info following @info or first gcov_info in the chain if
 * @info is %NULL.
 */
struct gcov_info *gcov_info_next(struct gcov_info *info)
{
	if (!info)
		return gcov_info_head;

	return info->next;
}

/**
 * gcov_info_link - link/add profiling data set to the list
 * @info: profiling data set
 */
void gcov_info_link(struct gcov_info *info)
{
	info->next = gcov_info_head;
	gcov_info_head = info;
}

/**
 * gcov_info_unlink - unlink/remove profiling data set from the list
 * @prev: previous profiling data set
 * @info: profiling data set
 */
void gcov_info_unlink(struct gcov_info *prev, struct gcov_info *info)
{
	if (prev)
		prev->next = info->next;
	else
		gcov_info_head = info->next;
}

/*
 * Determine whether a counter is active. Doesn't change at run-time.
 */
static int counter_active(struct gcov_info *info, unsigned int type)
{
	return info->merge[type] ? 1 : 0;
}

/* Determine number of active counters. Based on gcc magic. */
static unsigned int num_counter_active(struct gcov_info *info)
{
	unsigned int i;
	unsigned int result = 0;

	for (i = 0; i < GCOV_COUNTERS; i++) {
		if (counter_active(info, i))
			result++;
	}
	return result;
}

/**
 * gcov_info_reset - reset profiling data to zero
 * @info: profiling data set
 */
void gcov_info_reset(struct gcov_info *info)
{
	struct gcov_ctr_info *ci_ptr;
	unsigned int fi_idx;
	unsigned int ct_idx;

	for (fi_idx = 0; fi_idx < info->n_functions; fi_idx++) {
		ci_ptr = info->functions[fi_idx]->ctrs;

		for (ct_idx = 0; ct_idx < GCOV_COUNTERS; ct_idx++) {
			if (!counter_active(info, ct_idx))
				continue;

			memset(ci_ptr->values, 0,
					sizeof(gcov_type) * ci_ptr->num);
			ci_ptr++;
		}
	}
}

/**
 * gcov_info_is_compatible - check if profiling data can be added
 * @info1: first profiling data set
 * @info2: second profiling data set
 *
 * Returns non-zero if profiling data can be added, zero otherwise.
 */
int gcov_info_is_compatible(struct gcov_info *info1, struct gcov_info *info2)
{
	return (info1->stamp == info2->stamp);
}

/**
 * gcov_info_add - add up profiling data
 * @dst: profiling data set to which data is added
 * @src: profiling data set which is added
 *
 * Adds profiling counts of @src to @dst.
 */
void gcov_info_add(struct gcov_info *dst, struct gcov_info *src)
{
	struct gcov_ctr_info *dci_ptr;
	struct gcov_ctr_info *sci_ptr;
	unsigned int fi_idx;
	unsigned int ct_idx;
	unsigned int val_idx;

	for (fi_idx = 0; fi_idx < src->n_functions; fi_idx++) {
		dci_ptr = dst->functions[fi_idx]->ctrs;
		sci_ptr = src->functions[fi_idx]->ctrs;

		for (ct_idx = 0; ct_idx < GCOV_COUNTERS; ct_idx++) {
			if (!counter_active(src, ct_idx))
				continue;

			for (val_idx = 0; val_idx < sci_ptr->num; val_idx++)
				dci_ptr->values[val_idx] +=
					sci_ptr->values[val_idx];

			dci_ptr++;
			sci_ptr++;
		}
	}
}



/**
 * convert_to_gcda - convert profiling data set to gcda file format
 * @buffer: the buffer to store file data or %NULL if no data should be stored
 * @info: profiling data set to be converted
 *
 * Returns the number of bytes that were/would have been stored into the buffer.
 */
size_t convert_to_gcda(char *buffer, struct gcov_info *info)
{
	struct gcov_fn_info *fi_ptr;
	struct gcov_ctr_info *ci_ptr;
	unsigned int fi_idx;
	unsigned int ct_idx;
	unsigned int cv_idx;
	size_t pos = 0;

	/* File header. */
	pos += store_gcov_u32(buffer, pos, GCOV_DATA_MAGIC);
	pos += store_gcov_u32(buffer, pos, info->version);
	pos += store_gcov_u32(buffer, pos, info->stamp);

#if (__GNUC__ >= 12)
	/* Use zero as checksum of the compilation unit. */
	pos += store_gcov_u32(buffer, pos, 0);
#endif

	for (fi_idx = 0; fi_idx < info->n_functions; fi_idx++) {
		fi_ptr = info->functions[fi_idx];

		/* Function record. */
		pos += store_gcov_u32(buffer, pos, GCOV_TAG_FUNCTION);
		pos += store_gcov_u32(buffer, pos,
			GCOV_TAG_FUNCTION_LENGTH * GCOV_UNIT_SIZE);
		pos += store_gcov_u32(buffer, pos, fi_ptr->ident);
		pos += store_gcov_u32(buffer, pos, fi_ptr->lineno_checksum);
		pos += store_gcov_u32(buffer, pos, fi_ptr->cfg_checksum);

		ci_ptr = fi_ptr->ctrs;

		for (ct_idx = 0; ct_idx < GCOV_COUNTERS; ct_idx++) {
			if (!counter_active(info, ct_idx))
				continue;

			/* Counter record. */
			pos += store_gcov_u32(buffer, pos,
					      GCOV_TAG_FOR_COUNTER(ct_idx));
			pos += store_gcov_u32(buffer, pos,
				ci_ptr->num * 2 * GCOV_UNIT_SIZE);

			for (cv_idx = 0; cv_idx < ci_ptr->num; cv_idx++) {
				pos += store_gcov_u64(buffer, pos,
						      ci_ptr->values[cv_idx]);
			}

			ci_ptr++;
		}
	}

	return pos;
}
