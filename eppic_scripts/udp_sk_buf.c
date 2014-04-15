string
udp_opt()
{
	    return "l";
}

string
udp_usage()
{
	    return "\n";
}

static void
udp_showusage()
{
	    printf("usage : udp %s", udp_usage());
}

string
udp_help()
{
	    return "Help";
}

int
udp()
{
	int i;
	int size;
	struct udp_table *table;
	struct sock_common *off = 0;

	table = (struct udp_table *)&udp_table;

	for (i = 0; i < table->mask; i++) {
		struct hlist_nulls_node *pos;

		pos = table->hash[i].head.first;

		while (!((unsigned long)pos & 1)) {
			struct sock *sk;
			struct sk_buff *next;
			struct sk_buff_head *head;
			struct hlist_nulls_node *node;

			sk  = (struct sock *)((unsigned long)pos - ((unsigned long)&(off->skc_dontcopy_begin)));

			head = (struct sk_buff_head *)&(sk->sk_receive_queue);
			next = (struct sk_buff *)sk->sk_receive_queue.next;

			while (next != head)
			{
				struct sk_buff *buff = (struct sk_buff *)next;

				if (buff->data_len) {
					memset((char *)buff->data, 'L', buff->data_len);
					memset((char *)&(buff->data_len), 'L', 0x4);
				}

				next = buff->next;
			}

                        head = (struct sk_buff_head *)&(sk->sk_write_queue);
			next = (struct sk_buff *)sk->sk_write_queue.next;

			while (next != head)
			{
				struct sk_buff *buff = (struct sk_buff *)next;

				if (buff->data_len) {
					memset((char *)buff->data, 'L', buff->data_len);
					memset((char *)&(buff->data_len), 'L', 0x4);
				}

				next = buff->next;
                        }

			node = (struct hlist_nulls_node *)((unsigned long)sk + (unsigned long)&(off->skc_dontcopy_begin));
		        pos = node->next;
		}
	}
	return 1;
}
