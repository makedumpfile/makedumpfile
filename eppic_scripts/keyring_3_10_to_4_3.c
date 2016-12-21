string
skey_opt()
{
	    return "l";
}

string
skey_usage()
{
	    return "\n";
}

static void
skey_showusage()
{
	    printf("usage : skey %s", skey_usage());
}

string
skey_help()
{
	    return "Help";
}

int
skey()
{
	int i;
	struct list_head **tab;

	tab = &keyring_name_hash;

	for (i = 0; i < 32; i++)
	{
		struct list_head *next, *head;

		head = (struct list_head *) (tab + i);
		next = (struct list_head *) head->next;

		if (!next)
			continue;

		while (next != head)
		{
			struct key *mykey, *off = 0;

			mykey = (struct key *)((unsigned long)(next) - ((unsigned long)&(off->type_data)));

			memset((char *)&(mykey->payload.value), 'A', 0x8);
			memset((char *)mykey->payload.rcudata, 'A', 0x20);
			memset((char *)mykey->payload.data, 'A', 0x20);

			next = (struct list_head *) mykey->type_data.link.next;
		}
	}
	return 1;
}
