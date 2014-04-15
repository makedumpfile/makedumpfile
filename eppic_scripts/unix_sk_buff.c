string
sunix_opt()
{
	    return "l";
}

string
sunix_usage()
{
	    return "\n";
}

static void
sunix_showusage()
{
	    printf("usage : sunix %s", sunix_usage());
}

string
sunix_help()
{
	    return "Help";
}

int
sunix()
{
	int i;
	int size;
	struct hlist_head **tab;
	struct sock_common *off = 0;

	tab = &unix_socket_table;

	for (i = 0; i < 256; i++) {
		struct hlist_node *pos;
		struct hlist_node *node;
		struct hlist_head *tmp;

		tmp = (struct hlist_head *)(tab + i);
		pos = tmp->first;

		while (pos) {
			struct sock *sk;
			struct sk_buff *next;
			struct sk_buff_head *head;

			sk = (struct sock *)((unsigned long)pos - (unsigned long)&(off->skc_dontcopy_begin));

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

			node = (struct hlist_node *)((unsigned long)sk + (unsigned long)&(off->skc_dontcopy_begin));
			pos = node->next;
		}
	}
	return 1;
}
