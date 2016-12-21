string
ap_device_opt()
{
	    return "l";
}

string
ap_device_usage()
{
	    return "\n";
}

static void
ap_device_showusage()
{
	    printf("usage : ap_device %s", ap_device_usage());
}

string
ap_device_help()
{
	    return "Help";
}

int
ap_device()
{
	int i;
	struct list_head *next;
	struct list_head *head;
	struct ap_device *off = 0;

	head = (struct list_head *)&ap_device_list;
	next = (struct list_head *)head->next;

	if (!next)
		return 1;

	while (next != head)
	{
		struct ap_device *device;
		struct list_head *next1, *head1;

		device = (struct ap_device *)((unsigned long)next - ((unsigned long)&(off->list)));

		head1 = (struct list_head *)&(device->pendingq);
		next1 = (struct list_head *)device->pendingq.next;

		while (next1 != head1)
		{
			struct ap_message *apmsg;
			apmsg = (struct ap_message *)next1;

			if (apmsg->length) {
				memset((char *)apmsg->message, 'L', apmsg->length);
				memset((char *)&(apmsg->length), 'L', 0x8);
			}

			next1 = (struct list_head *)apmsg->list.next;
		}

		head1 = (struct list_head *)&(device->requestq);
		next1 = (struct list_head *)device->requestq.next;

		while (next1 != head1)
		{
			struct ap_message *apmsg;
			apmsg = (struct ap_message *)next1;

			if (apmsg->length) {
				memset((char *)apmsg->message, 'L', apmsg->length);
				memset((char *)&(apmsg->length), 'L', 0x8);
			}

			next1 = (struct list_head *)apmsg->list.next;
		}

		next = (struct list_head *)device->list.next;
	}

	return 1;
}
