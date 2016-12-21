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

	memset(dir->d_iname, 0, 0x20);
	memset(dir->d_name.name, 0, 0x20);

	head = (struct list_head *)&(dir->d_subdirs);
	next = (struct list_head *)dir->d_subdirs.next;

	while (next != head)
	{
		struct dentry *child, *off = 0;

		child = (struct dentry *)((unsigned long)next - (unsigned long)&(off->d_u));
		rm_names(child);
		next = child->d_u.d_child.next;
	}

	return;
}

int
vfs()
{
	int i;
	struct list_head *tab;

	tab = (struct list_head *)mount_hashtable;

	for (i = 0; i < 256; i++)
	{
		struct list_head *head, *next;

		head = (struct list_head *) (tab + i);
		next = (struct list_head *) head->next;

		if (!next)
			continue;

		while (next != head)
		{
			struct mount *mntfs;
			struct dentry *root;

			mntfs = (struct mount *)((unsigned long)next);
			root = (struct dentry *)mntfs->mnt.mnt_root;
			rm_names(root);
			next = mntfs->mnt_hash.next;
		}
	}
	return 1;
}
