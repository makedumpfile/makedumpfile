string
tcp_opt()
{
	    return "l";
}

string
tcp_usage()
{
	    return "\n";
}

static void
tcp_showusage()
{
	    printf("usage : tcp %s", tcp_non_legacy_usage());
}

string
tcp_help()
{
	    return "Help";
}

int
tcp()
{
	int i;
	struct inet_hashinfo *tab;
	struct sock_common *off = 0;

	tab = &tcp_hashinfo;

	for (i = 0; i < 32; i++) {
		struct hlist_nulls_node *pos;

		pos = tab->listening_hash[i].head.first;

		while (!((unsigned long)pos & 1)) {
			struct sock *sk;
			struct sk_buff *next;
			struct sk_buff_head *head;
			struct hlist_nulls_node *node;

			sk  = (struct sock *)((unsigned long)pos - (unsigned long)&(off->skc_dontcopy_begin));

			head = (struct sk_buff_head *)&(sk->sk_receive_queue);
			next = (struct sk_buff *)sk->sk_receive_queue.next;

			while (next != head)
			{
				struct sk_buff *buff = (struct sk_buff *) next;

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
				struct sk_buff *buff = (struct sk_buff *) next;

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
