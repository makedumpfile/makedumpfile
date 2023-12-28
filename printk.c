#include "makedumpfile.h"
#include <ctype.h>

/* convenience struct for passing many values to helper functions */
struct prb_map {
	char		*prb;

	char		*desc_ring;
	unsigned long	desc_ring_count;
	char		*descs;
	char		*infos;

	char		*text_data_ring;
	unsigned long	text_data_ring_size;
	char		*text_data;
};

/*
 * desc_state and DESC_* definitions taken from kernel source:
 *
 * kernel/printk/printk_ringbuffer.h
 */

/* The possible responses of a descriptor state-query. */
enum desc_state {
	desc_miss	=  -1,	/* ID mismatch (pseudo state) */
	desc_reserved	= 0x0,	/* reserved, in use by writer */
	desc_committed	= 0x1,	/* committed by writer, could get reopened */
	desc_finalized	= 0x2,	/* committed, no further modification allowed */
	desc_reusable	= 0x3,	/* free, not yet used by any writer */
};

#define DESC_SV_BITS		(sizeof(unsigned long) * 8)
#define DESC_FLAGS_SHIFT	(DESC_SV_BITS - 2)
#define DESC_FLAGS_MASK		(3UL << DESC_FLAGS_SHIFT)
#define DESC_STATE(sv)		(3UL & (sv >> DESC_FLAGS_SHIFT))
#define DESC_ID_MASK		(~DESC_FLAGS_MASK)
#define DESC_ID(sv)		((sv) & DESC_ID_MASK)

/*
 * get_desc_state() taken from kernel source:
 *
 * kernel/printk/printk_ringbuffer.c
 */

/* Query the state of a descriptor. */
static enum desc_state get_desc_state(unsigned long id,
				      unsigned long state_val)
{
	if (id != DESC_ID(state_val))
		return desc_miss;

	return DESC_STATE(state_val);
}

static int
dump_record(struct prb_map *m, unsigned long id)
{
	unsigned long long ts_nsec;
	unsigned long state_var;
	unsigned short text_len;
	enum desc_state state;
	unsigned long begin;
	unsigned long next;
	char buf[BUFSIZE];
	ulonglong nanos;
	int indent_len;
	int buf_need;
	char *bufp;
	char *text;
	char *desc;
	char *inf;
	ulong rem;
	char *p;
	int i;

	desc = m->descs + ((id % m->desc_ring_count) * SIZE(prb_desc));

	/* skip non-committed record */
	state_var = ULONG(desc + OFFSET(prb_desc.state_var) + OFFSET(atomic_long_t.counter));
	state = get_desc_state(id, state_var);
	if (state != desc_committed && state != desc_finalized)
		return TRUE;

	begin = ULONG(desc + OFFSET(prb_desc.text_blk_lpos) + OFFSET(prb_data_blk_lpos.begin)) %
			m->text_data_ring_size;
	next = ULONG(desc + OFFSET(prb_desc.text_blk_lpos) + OFFSET(prb_data_blk_lpos.next)) %
			m->text_data_ring_size;

	/* skip data-less text blocks */
	if (begin == next)
		return TRUE;

	inf = m->infos + ((id % m->desc_ring_count) * SIZE(printk_info));

	text_len = USHORT(inf + OFFSET(printk_info.text_len));

	/* handle wrapping data block */
	if (begin > next)
		begin = 0;

	/* skip over descriptor ID */
	begin += sizeof(unsigned long);

	/* handle truncated messages */
	if (next - begin < text_len)
		text_len = next - begin;

	text = m->text_data + begin;

	ts_nsec = ULONGLONG(inf + OFFSET(printk_info.ts_nsec));
	nanos = (ulonglong)ts_nsec / (ulonglong)1000000000;
	rem = (ulonglong)ts_nsec % (ulonglong)1000000000;

	bufp = buf;
	bufp += sprintf(buf, "[%5lld.%06ld] ", nanos, rem/1000);

	if (OFFSET(printk_info.caller_id) != NOT_FOUND_STRUCTURE) {
		const unsigned int cpuid = 0x80000000;
		char cidbuf[PID_CHARS_MAX];
		unsigned int cid;

		/* Get id type, isolate id value in cid for print */
		cid = UINT(inf + OFFSET(printk_info.caller_id));
		sprintf(cidbuf, "%c%u", (cid & cpuid) ? 'C' : 'T', cid & ~cpuid);
		bufp += sprintf(bufp, "[%*s] ", PID_CHARS_DEFAULT, cidbuf);
	}

	indent_len = strlen(buf);

	/* How much buffer space is needed in the worst case */
	buf_need = MAX(sizeof("\\xXX\n"), sizeof("\n") + indent_len);

	for (i = 0, p = text; i < text_len; i++, p++) {
		if (bufp - buf >= sizeof(buf) - buf_need) {
			if (!write_and_check_space(info->fd_dumpfile, buf,
						   bufp - buf, "log",
						   info->name_dumpfile))
				return FALSE;
			bufp = buf;
		}

		if (*p == '\n')
			bufp += sprintf(bufp, "\n%-*s", indent_len, "");
		else if (isprint(*p) || isspace(*p))
			*bufp++ = *p;
		else
			bufp += sprintf(bufp, "\\x%02x", *p);
	}

	*bufp++ = '\n';

	return write_and_check_space(info->fd_dumpfile, buf, bufp - buf,
				     "log", info->name_dumpfile);
}

int
dump_lockless_dmesg(void)
{
	unsigned long long clear_seq;
	unsigned long head_id;
	unsigned long tail_id;
	unsigned long kaddr;
	unsigned long id;
	struct prb_map m;
	int ret = FALSE;

	/* setup printk_ringbuffer */
	if (!readmem(VADDR, SYMBOL(prb), &kaddr, sizeof(kaddr))) {
		ERRMSG("Can't get the prb address.\n");
		return ret;
	}

	m.prb = malloc(SIZE(printk_ringbuffer));
	if (!m.prb) {
		ERRMSG("Can't allocate memory for prb.\n");
		return ret;
	}
	if (!readmem(VADDR, kaddr, m.prb, SIZE(printk_ringbuffer))) {
		ERRMSG("Can't get prb.\n");
		goto out_prb;
	}

	/* setup descriptor ring */
	m.desc_ring = m.prb + OFFSET(printk_ringbuffer.desc_ring);
	m.desc_ring_count = 1 << UINT(m.desc_ring + OFFSET(prb_desc_ring.count_bits));

	kaddr = ULONG(m.desc_ring + OFFSET(prb_desc_ring.descs));
	m.descs = malloc(SIZE(prb_desc) * m.desc_ring_count);
	if (!m.descs) {
		ERRMSG("Can't allocate memory for prb.desc_ring.descs.\n");
		goto out_prb;
	}
	if (!readmem(VADDR, kaddr, m.descs,
		     SIZE(prb_desc) * m.desc_ring_count)) {
		ERRMSG("Can't get prb.desc_ring.descs.\n");
		goto out_descs;
	}

	kaddr = ULONG(m.desc_ring + OFFSET(prb_desc_ring.infos));
	m.infos = malloc(SIZE(printk_info) * m.desc_ring_count);
	if (!m.infos) {
		ERRMSG("Can't allocate memory for prb.desc_ring.infos.\n");
		goto out_descs;
	}
	if (!readmem(VADDR, kaddr, m.infos, SIZE(printk_info) * m.desc_ring_count)) {
		ERRMSG("Can't get prb.desc_ring.infos.\n");
		goto out_infos;
	}

	/* setup text data ring */
	m.text_data_ring = m.prb + OFFSET(printk_ringbuffer.text_data_ring);
	m.text_data_ring_size = 1 << UINT(m.text_data_ring + OFFSET(prb_data_ring.size_bits));

	kaddr = ULONG(m.text_data_ring + OFFSET(prb_data_ring.data));
	m.text_data = malloc(m.text_data_ring_size);
	if (!m.text_data) {
		ERRMSG("Can't allocate memory for prb.text_data_ring.data.\n");
		goto out_infos;
	}
	if (!readmem(VADDR, kaddr, m.text_data, m.text_data_ring_size)) {
		ERRMSG("Can't get prb.text_data_ring.\n");
		goto out_text_data;
	}

	/* ready to go */

	tail_id = ULONG(m.desc_ring + OFFSET(prb_desc_ring.tail_id) +
			OFFSET(atomic_long_t.counter));
	head_id = ULONG(m.desc_ring + OFFSET(prb_desc_ring.head_id) +
			OFFSET(atomic_long_t.counter));
	if (info->flag_partial_dmesg && SYMBOL(clear_seq) != NOT_FOUND_SYMBOL) {
		if (!readmem(VADDR, SYMBOL(clear_seq), &clear_seq,
			     sizeof(clear_seq))) {
			ERRMSG("Can't get clear_seq.\n");
			goto out_text_data;
		}
		if (SIZE(latched_seq) != NOT_FOUND_STRUCTURE) {
			kaddr = SYMBOL(clear_seq) + OFFSET(latched_seq.val) +
				(clear_seq & 0x1) * sizeof(clear_seq);
			if (!readmem(VADDR, kaddr, &clear_seq,
				     sizeof(clear_seq))) {
				ERRMSG("Can't get latched clear_seq.\n");
				goto out_text_data;
			}
		}
		tail_id = head_id - head_id % m.desc_ring_count +
			  clear_seq % m.desc_ring_count;
	}

	if (!open_dump_file()) {
		ERRMSG("Can't open output file.\n");
		goto out_text_data;
	}

	for (id = tail_id; id != head_id; id = (id + 1) & DESC_ID_MASK) {
		if (!dump_record(&m, id))
			goto out_text_data;
	}

	/* dump head record */
	if (!dump_record(&m, id))
		goto out_text_data;

	if (!close_files_for_creating_dumpfile())
		goto out_text_data;

	ret = TRUE;
out_text_data:
	free(m.text_data);
out_infos:
	free(m.infos);
out_descs:
	free(m.descs);
out_prb:
	free(m.prb);
	return ret;
}
