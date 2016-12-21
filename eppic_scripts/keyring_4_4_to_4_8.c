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

#define ASSOC_ARRAY_FAN_OUT 16
#define ASSOC_ARRAY_FAN_MASK            (ASSOC_ARRAY_FAN_OUT - 1)
#define ASSOC_ARRAY_LEVEL_STEP          (ilog2(ASSOC_ARRAY_FAN_OUT))
#define ASSOC_ARRAY_LEVEL_STEP_MASK     (ASSOC_ARRAY_LEVEL_STEP - 1)
#define ASSOC_ARRAY_KEY_CHUNK_MASK      (ASSOC_ARRAY_KEY_CHUNK_SIZE - 1)
#define ASSOC_ARRAY_KEY_CHUNK_SHIFT     (ilog2(BITS_PER_LONG))
#define ASSOC_ARRAY_PTR_TYPE_MASK 0x1UL
#define ASSOC_ARRAY_PTR_LEAF_TYPE 0x0UL /* Points to leaf (or nowhere) */
#define ASSOC_ARRAY_PTR_META_TYPE 0x1UL /* Points to node or shortcut */
#define ASSOC_ARRAY_PTR_SUBTYPE_MASK    0x2UL
#define ASSOC_ARRAY_PTR_NODE_SUBTYPE    0x0UL
#define ASSOC_ARRAY_PTR_SHORTCUT_SUBTYPE 0x2UL

/* Keyring stuff */
#define KEYRING_PTR_SUBTYPE     0x2UL

static int keyring_ptr_is_keyring(const struct assoc_array_ptr *x)
{
	return (unsigned long)x & KEYRING_PTR_SUBTYPE;
}

static int assoc_array_ptr_is_meta(const struct assoc_array_ptr *x)
{
	return (unsigned long)x & ASSOC_ARRAY_PTR_TYPE_MASK;
}

static int assoc_array_ptr_is_leaf(const struct assoc_array_ptr *x)
{
	return !assoc_array_ptr_is_meta(x);
}
static int assoc_array_ptr_is_shortcut(const struct assoc_array_ptr *x)
{
	return (unsigned long)x & ASSOC_ARRAY_PTR_SUBTYPE_MASK;
}
static int assoc_array_ptr_is_node(const struct assoc_array_ptr *x)
{
	return !assoc_array_ptr_is_shortcut(x);
}

static void *assoc_array_ptr_to_leaf(const struct assoc_array_ptr *x)
{
	return (void *)((unsigned long)x & ~ASSOC_ARRAY_PTR_TYPE_MASK);
}

static
unsigned long __assoc_array_ptr_to_meta(const struct assoc_array_ptr *x)
{
	return (unsigned long)x &
		~(ASSOC_ARRAY_PTR_SUBTYPE_MASK | ASSOC_ARRAY_PTR_TYPE_MASK);
}
static
struct assoc_array_node *assoc_array_ptr_to_node(const struct assoc_array_ptr *x)
{
	return (struct assoc_array_node *)__assoc_array_ptr_to_meta(x);
}
static
struct assoc_array_shortcut *assoc_array_ptr_to_shortcut(const struct assoc_array_ptr *x)
{
	return (struct assoc_array_shortcut *)__assoc_array_ptr_to_meta(x);
}

static
struct assoc_array_ptr *__assoc_array_x_to_ptr(const void *p, unsigned long t)
{
	return (struct assoc_array_ptr *)((unsigned long)p | t);
}
static
struct assoc_array_ptr *assoc_array_leaf_to_ptr(const void *p)
{
	return __assoc_array_x_to_ptr(p, ASSOC_ARRAY_PTR_LEAF_TYPE);
}
static
struct assoc_array_ptr *assoc_array_node_to_ptr(const struct assoc_array_node *p)
{
	return __assoc_array_x_to_ptr(
		p, ASSOC_ARRAY_PTR_META_TYPE | ASSOC_ARRAY_PTR_NODE_SUBTYPE);
}

static
struct assoc_array_ptr *assoc_array_shortcut_to_ptr(const struct assoc_array_shortcut *p)
{
	return __assoc_array_x_to_ptr(
		p, ASSOC_ARRAY_PTR_META_TYPE | ASSOC_ARRAY_PTR_SHORTCUT_SUBTYPE);
}

/* Keyring stuff */
static inline struct key *keyring_ptr_to_key(const struct assoc_array_ptr *x)
{
	void *object = assoc_array_ptr_to_leaf(x);
	return (struct key *)((unsigned long)object & ~KEYRING_PTR_SUBTYPE);
}

/* BEGIN: struct key access */
struct keyring_index_key *get_index_key_from_key(struct key *key)
{
	return (struct keyring_index_key *)((unsigned long)&(key->flags)
					    + sizeof(key->flags));
}

struct key_type *get_type_from_key(struct key *key)
{
	return (struct key_type *)((unsigned long)&(key->flags)
				   + sizeof(key->flags));
}

char *get_description_from_key(struct key *key)
{
	return (char *)((unsigned long)&(key->flags)
				   + sizeof(key->flags)
				   + sizeof(struct key_type *));
}

union key_payload *get_payload_from_key(struct key *key)
{
	return (union key_payload *)((unsigned long)&(key->flags)
				     + sizeof(key->flags)
				     + sizeof(struct keyring_index_key));
}

struct list_head *get_name_link_from_key(struct key *key)
{
	return (struct list_head *)((unsigned long)&(key->flags)
					 + sizeof(key->flags)
					 + sizeof(struct keyring_index_key));
}

struct assoc_array *get_keys_from_key(struct key *key)
{
	return (struct assoc_array *)((unsigned long)&(key->flags)
				      + sizeof(key->flags)
				      + sizeof(struct keyring_index_key)
				      + sizeof(struct list_head));
}
/* END: struct key access */

static void delete_keyring_subtree(struct assoc_array_ptr *root)
{
	struct assoc_array_shortcut *shortcut;
	struct assoc_array_node *node;
	struct assoc_array_ptr *cursor, *parent;
	int slot = -1;

	cursor = root;
	if (!cursor) {
		return;
	}

	if (assoc_array_ptr_is_shortcut(cursor)) {
		/* Descend through a shortcut */
		shortcut = assoc_array_ptr_to_shortcut(cursor);
		parent = cursor;
		cursor = shortcut->next_node;
	}

	node = assoc_array_ptr_to_node(cursor);
	slot = 0;

	if(node->nr_leaves_on_branch <= 0) return;

	do {
		for (; slot < ASSOC_ARRAY_FAN_OUT; slot++) {
			struct assoc_array_ptr *ptr = node->slots[slot];

			if (!ptr)
				continue;
			if (assoc_array_ptr_is_meta(ptr)) {
				parent = cursor;
				cursor = ptr;
				if (assoc_array_ptr_is_shortcut(cursor)) {
					/* Descend through a shortcut */
					shortcut = assoc_array_ptr_to_shortcut(cursor);
					parent = cursor;
					cursor = shortcut->next_node;
				}
				node = assoc_array_ptr_to_node(cursor);
				slot = 0;
			} else {
				struct key *leaf;
				struct keyring_index_key *index_key;
				char *description;
				void *payload_ptr;
				int i,j;

				/* no need to delete keyrings, only data */
				if(keyring_ptr_is_keyring(ptr))
					continue;

				/* delete the leaf payload */
				leaf = (struct key *)assoc_array_ptr_to_leaf(ptr);
				index_key = get_index_key_from_key(leaf);
				/*
				   Now delete the keys of the different key types.
				   The following key types are handled for now:
				   user, ceph, pkcs7_test, asymmetric(X509), rxpc

				   The following key types are NOT  handled (yet):
				   dns_resolver (no secret keys, just used for DNS)

				   Add a new else if() for new key types.
				*/
				if(getstr(index_key->type->name) == "user") {
					struct user_key_payload **user_key_payload;
					unsigned short datalen;

					payload_ptr=(void *)get_payload_from_key(leaf);
					user_key_payload = (struct user_key_payload **)payload_ptr;
					datalen = (*user_key_payload)->datalen;
					memset((char *)&(*user_key_payload)->data, 'A', datalen);
				} else if(getstr(index_key->type->name) == "ceph") {
					struct ceph_crypto_key **ceph_payload;
					int len;

					payload_ptr=(void *)get_payload_from_key(leaf);
					ceph_payload = (struct ceph_crypto_key **)payload_ptr;
					len = (*ceph_payload)->len;
					memset((char *)&(*ceph_payload)->key, 'A', len);
				} else if(getstr(index_key->type->name) == "pkcs7_test") {
					struct user_key_payload **user_key_payload;
					unsigned short datalen;

					payload_ptr=(void *)get_payload_from_key(leaf);
					user_key_payload = (struct user_key_payload **)payload_ptr;
					datalen = (*user_key_payload)->datalen;
					memset((char *)&(*user_key_payload)->data, 'A', datalen);
				} else if(getstr(index_key->type->name) == "asymmetric") {
					struct public_key **public_key;
					unsigned short keylen;

					/* data[0] is asym_crypto */
					payload_ptr=(void *)get_payload_from_key(leaf);
					public_key = (struct public_key **)payload_ptr;
					keylen = (*public_key)->keylen;
					memset((char *)&(*public_key)->key, 'A', keylen);
				} else if(getstr(index_key->type->name) == ".request_key_auth") {
					struct request_key_auth **request_key;
					unsigned short datalen;

					payload_ptr=(void *)get_payload_from_key(leaf);
					request_key = (struct request_key_auth **)payload_ptr;
					datalen = leaf->datalen;
					memset((char *)&(*request_key)->data, 'A', datalen);
				} else if(getstr(index_key->type->name) == "rxrpc") {
					struct rxrpc_key_token **rxrpc_key_token, *token;
					struct rxkad_key *kad;
					struct rxk5_key *k5;
					int token_count = 0;

					payload_ptr=(void *)get_payload_from_key(leaf);
					rxrpc_key_token = (struct rxrpc_key_token **)payload_ptr;
					for(; rxrpc_key_token;
					    rxrpc_key_token = &(*rxrpc_key_token)->next,
						    token_count++) {
						token = *rxrpc_key_token;
						switch(token->security_index) {
						case 2 : /* RXRPC_SECURITY_RXKAD */
							/* anonymous union, use pointer arithmetic */
							kad = token->next +
								sizeof(struct rxrpc_key_token *);
							memset(&kad.session_key, 'A', 8);
							memset(&kad.ticket, 'A', kad.ticket_len);
							break;
						case 5 : /* RXRPC_SECURITY_RXK5 */
							/* anonymous union, use pointer arithmetic */
							k5 = token->next +
								sizeof(struct rxrpc_key_token *);
							memset(k5.ticket, 'A', k5.ticket_len);
							memset(k5.ticket2, 'A', k5.ticket2_len);
							memset(k5.session.data, 'A', k5.session.data_len);
							memset(k5->addresses.data, 'A', k5->addresses.data_len);
							memset(k5->authdata.data, 'A', k5->authdata.data_len);
							break;
						default :
							printf("WARNING: unknown security index: %d\n",
								token->security_index);
						}
						/* max number of tokens = 8 */
						if(token_count > 8) {
							printf("WARNING: too many rxrpc tokens!\n");
							break;
						}
					}
				} else if(getstr(index_key->type->name) == "dns_resolver") {
					/* nothing to do here, no secret data */
				} else if(getstr(index_key->type->name) == "big_key") {
					printf("WARNING: key_type=big_key not handled!\n");
				} else {
					printf("WARNING: unsupported key type = %s!\n",
					       getstr(index_key->type->name));
				}
			}
		}

		parent = node->back_pointer;
		slot = node->parent_slot;
		if (parent) {
			/* Move back up to the parent */
			if (assoc_array_ptr_is_shortcut(parent)) {
				shortcut = assoc_array_ptr_to_shortcut(parent);
				cursor = parent;
				parent = shortcut->back_pointer;
				slot = shortcut->parent_slot;
			}

			/* Ascend to next slot in parent node */
			cursor = parent;
			node = assoc_array_ptr_to_node(cursor);
			slot++;
		}
	} while(parent);

	return;
}

void delete_keyring(struct assoc_array *keyring)
{
	delete_keyring_subtree(keyring->root);
}

int
skey()
{
	int i,j,k;
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
			struct list_head *name_link;
			struct assoc_array *keys;

			mykey = (struct key *)((unsigned long)(next)
					       - (unsigned long)&(off->flags)
					       - sizeof(off->flags)
					       - sizeof(struct keyring_index_key));
			name_link = get_name_link_from_key(mykey);
			keys = get_keys_from_key(mykey);
			delete_keyring(keys);
			next = (struct list_head *) name_link->next;
		}
	}
	return 1;
}
