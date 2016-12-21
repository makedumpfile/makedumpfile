string
vfs_opt()
{
	    return "l";
}

string
vfs_usage()
{
	    return "\n";
}

static void
vfs_showusage()
{
	    printf("usage : vfs %s", vfs_usage());
}

string
vfs_help()
{
	    return "Help";
}

void
rm_names(struct dentry *dir)
{
	struct list_head *next, *head;
	unsigned int hash_len;
	int i;

	memset(dir->d_iname, 0, 0x20);
	hash_len = *((unsigned int *)&dir->d_name);
	memset(dir->d_name.name, 0, hash_len);

	head = (struct list_head *)&(dir->d_subdirs);
	next = (struct list_head *)dir->d_subdirs.next;

	while (next != head)
	{
		struct dentry *child, *off = 0;

		child = (struct dentry *)((unsigned long)next - (unsigned long)&(off->d_child));
		rm_names(child);
		next = child->d_child.next;
	}

	return;
}

int
vfs()
{
	int i;
	struct hlist_bl_head *tab;
	unsigned int d_hash_size = d_hash_mask;

	tab = (struct hlist_bl_head *)dentry_hashtable;

	for (i = 0; i < d_hash_size; i++)
	{
		struct hlist_bl_head *head;
		struct hlist_bl_node *head_node, *next;

		head = (struct hlist_bl_head *) (tab + i);
		head_node = head->first;
		if (!head_node)
			continue;

		next = head_node;

		while (next)
		{
			struct dentry *root, *off = 0;

			root = (struct dentry *)((unsigned long)next - (unsigned long)&(off->d_hash));
			rm_names(root);
			next = next->next;
		}
	}
	return 1;
}
