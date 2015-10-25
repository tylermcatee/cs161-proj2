#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/ec.h>

#include "block.h"
#include "common.h"
#include "transaction.h"

typedef int (*compfn)(const void*, const void*);
int compare_by_height(struct block *b1, struct block *b2);

/* Usage: ./balances *.blk
 * Reads in a list of block files and outputs a table of public key hashes and
 * their balance in the longest chain of blocks. In case there is more than one
 * chain of the longest length, chooses one arbitrarily. */

/* If a block has height 0, it must have this specific hash. */
const hash_output GENESIS_BLOCK_HASH = {
	0x00, 0x00, 0x00, 0x0e, 0x5a, 0xc9, 0x8c, 0x78, 0x98, 0x00, 0x70, 0x2a, 0xd2, 0xa6, 0xf3, 0xca,
	0x51, 0x0d, 0x40, 0x9d, 0x6c, 0xca, 0x89, 0x2e, 0xd1, 0xc7, 0x51, 0x98, 0xe0, 0x4b, 0xde, 0xec,
};

struct blockchain_node {
	struct blockchain_node *parent;
	struct block b;
	int is_valid;
};

/* A simple linked list to keep track of account balances. */
struct balance {
	struct ecdsa_pubkey pubkey;
	int balance;
	struct balance *next;
};

/* Add or subtract an amount from a linked list of balances. Call it like this:
 *   struct balance *balances = NULL;
 *
 *   // reward_tx increment.
 *   balances = balance_add(balances, &b.reward_tx.dest_pubkey, 1);
 *
 *   // normal_tx increment and decrement.
 *   balances = balance_add(balances, &b.normal_tx.dest_pubkey, 1);
 *   balances = balance_add(balances, &prev_transaction.dest_pubkey, -1);
 */
static struct balance *balance_add(struct balance *balances,
	struct ecdsa_pubkey *pubkey, int amount)
{
	struct balance *p;

	for (p = balances; p != NULL; p = p->next) {
		if ((byte32_cmp(p->pubkey.x, pubkey->x) == 0)
			&& (byte32_cmp(p->pubkey.y, pubkey->y) == 0)) {
			p->balance += amount;
			return balances;
		}
	}

	/* Not found; create a new list element. */
	p = malloc(sizeof(struct balance));
	if (p == NULL)
		return NULL;
	p->pubkey = *pubkey;
	p->balance = amount;
	p->next = balances;

	return p;
}

/** A comparator for the qsort function that sorts an array of
  * block structures by height. */
int compare_by_height(struct block *b1, struct block *b2)
{
	if (b1->height < b2->height) {
		return -1;
	}
	else if (b1->height > b2->height) {
		return 1;
	}
	else {
		return 0;
	}
}

/**	Returns 1 if the block is valid before tree construction and 0 otherwise.
  * Does not take into requirements where ancestor must be known.
  */
int valid_block_before_tree(struct block b) {
	hash_output h;
	block_hash(&b, h);

	if (b.height == 0) {
		// Gensis block

		// If the hash isn't the genesis block hash, return 0
		if (byte32_cmp(h, GENESIS_BLOCK_HASH) != 0) {
			return 0;
		}
	} else {
		// Regular block

		// If the hash isn't less htan the target hash, return 0
		if (!hash_output_is_below_target(h)) {
			return 0;
		}
	}

	/** The height of both of the block's transactions must be 
	  * equal to the block's height. */
	if (b.height != b.reward_tx.height || b.height != b.normal_tx.height) {
		return 0;
	}

	/** The reward_tx.prev_transaction_hash, reward_tx.src_signature.r, and
	  * reward_tx.src_signature.s members must be zero—reward transactions are not
	  * signed and do not come from another public key. (Use the byte32_zero function.) */
	if (!byte32_is_zero(b.reward_tx.prev_transaction_hash) || !byte32_is_zero(b.reward_tx.src_signature.r) ||
		!byte32_is_zero(b.reward_tx.src_signature.s)) {
		return 0;
	}

	return 1;
}

/** Returns 1 if the node is valid after tree construction and 0 otherwise.
*/
int valid_node_after_tree(struct blockchain_node node) {
	/** If normal_tx.prev_transaction_hash is zero, then there is no 
	  * normal transaction in this block. */
	if (!byte32_is_zero(node.b.normal_tx.prev_transaction_hash)) {
		// But if it is not zero

		/** The transaction referenced by normal_tx.prev_transaction_hash 
		  * must exist as either the reward_tx or normal_tx of an ancestor 
		  * block. (Use the transaction_hash function.) */
		struct blockchain_node *ancestor = node.parent;
		int found = 0;
		// Retain the previous transaction for the next one
		struct transaction *previous_transaction;
		while (ancestor) {
			// Check reward_tx hash
			hash_output reward_tx_hash;
			transaction_hash(&ancestor->b.reward_tx, reward_tx_hash);
			if (byte32_cmp(node.b.normal_tx.prev_transaction_hash, reward_tx_hash) == 0) {
				found = 1;
				previous_transaction = &ancestor->b.reward_tx;
				break;
			}
			// Check normal_tx hash
			hash_output normal_tx_hash;
			transaction_hash(&ancestor->b.normal_tx, normal_tx_hash);
			if (byte32_cmp(node.b.normal_tx.prev_transaction_hash, normal_tx_hash) == 0) {
				found = 1;
				previous_transaction = &ancestor->b.normal_tx;
				break;
			}
			ancestor = ancestor->parent;
		}
		// We didn't find a matching hash, return 0.
		if (found != 1) {
			return 0;
		}

		/** The signature on normal_tx must be valid using the dest_pubkey of the previous
		  * transaction that has hash value normal_tx.prev_transaction_hash. (Use the
		  * transaction_verify function.) */
		if (transaction_verify(&node.b.normal_tx, previous_transaction) == 1) {
			// Success
		} else {
			// Failure
			return 0;
		}

		/** The coin must not have already been spent: there must be no ancestor block that
		  * has the same normal_tx.prev_transaction_hash.
		  */
		ancestor = node.parent;
		while (ancestor) {
			if (byte32_cmp(node.b.normal_tx.prev_transaction_hash, ancestor->b.normal_tx.prev_transaction_hash) == 0) {
				return 0;
			}
			ancestor = ancestor->parent;
		}
	}

	return 1;
}

/**
 *	Searches through blocknodes to try to find the parent of block b, up to maximum
 */
int parentnode_of_block(struct block b, struct blockchain_node *blocknodes, int maximum) {
	// Search for a block with the prev_block_hash
	int i;
	for (i = 0; i < maximum; i++) {
		struct blockchain_node node = blocknodes[i];
		hash_output node_hash;
		block_hash(&node.b, node_hash);
		if (byte32_cmp(node_hash, b.prev_block_hash) == 0) {
			return i;
		}
	}
	return -1;
}

int main(int argc, char *argv[])
{
	int i;
	int blockc = argc - 1;
	struct block *blocks = malloc(blockc * sizeof(struct block));
	

	/* Read input block files. */
	for (i = 1; i < argc; i++) {
		char *filename;
		struct block b;
		int rc;

		filename = argv[i];
		rc = block_read_filename(&b, filename);
		if (rc != 1) {
			fprintf(stderr, "could not read %s\n", filename);
			exit(1);
		}

		// Add the block to the blocks array
		blocks[i - 1] = b;
		/* TODO */
		/* Feel free to add/modify/delete any code you need to. */
	}

	// Sort the blocks by height
	qsort((void *)blocks, blockc, sizeof(struct block), (compfn)compare_by_height);

	/** Now that we have the blocks sorted by height, we can move
	  * them into a block chain style of organization. */

	// Create a list of the nodes still sorted by height order.
	struct blockchain_node *blocknodes = malloc(blockc * sizeof(struct blockchain_node));
	// Valid block count
	int vblockc = 0;
	for (i = 0; i < blockc; i++) {
		struct block b = blocks[i];
		// Only add it if it is valid so far
		if (valid_block_before_tree(b)) {
			if (b.height == 0) {
				// Create the block, parent is NULL
				struct blockchain_node node = {.parent = NULL, .is_valid = 1, .b = b};
				// Add it to the list of nodes
				blocknodes[vblockc] = node;
				vblockc += 1;
			} else {
				// Height greater than 0, need to find parent
				int parent_index = parentnode_of_block(b, blocknodes, i);
				if (parent_index == -1) {
					// Create the block, parent is "parent"
					struct blockchain_node node = {.parent = NULL, .is_valid = 0, .b = b};
					// Add it to the list of nodes
					blocknodes[vblockc] = node;
				} else {
					// Create the block, parent is "parent"
					struct blockchain_node node = {.parent = &blocknodes[parent_index], .is_valid = 1, .b = b};
					// Add it to the list of nodes
					blocknodes[vblockc] = node;
				}
				
				vblockc += 1;
			}
		} else {
			// Invalid block, we do not increment vblockc
		}
	}

	// Now that we have a tree we can do further checks on validity
	// that requires ancestry
	for (i = 0; i < vblockc; i++) {
		struct blockchain_node *blocknode = &blocknodes[i];
		if (!valid_node_after_tree(*blocknode)) {
			blocknode->is_valid = 0;
		}
	}

	// Now go through and try to find the longest chain.
	int leaf_idx;
	for (leaf_idx = vblockc - 1; leaf_idx >= 0; leaf_idx--) {
		// See if we can traverse all the way without it being invalid
		struct blockchain_node *node = &blocknodes[leaf_idx];
		int valid = 1;
		while (node) {
			if (!node->is_valid) {
				valid = 0;
			}
			node = node->parent;
		}
		if (valid) {
			// Found it.
			break;
		}
	}

	// We now know the longest chain starts at index leaf_idx and can create the path to track for balances.
	int chain_height = blocknodes[leaf_idx].b.height;
	int chain_length = chain_height + 1;
	struct blockchain_node *longest_chain = malloc(chain_length * sizeof(struct blockchain_node));
	int chain_idx = chain_height;
	struct blockchain_node *node = &blocknodes[leaf_idx];
	while (node) {
		longest_chain[chain_idx] = *node;
		chain_idx--;
		node = node->parent;
	}

	// We can now go through the chain and construct the balances
	for (i = 0; i < chain_length; i++) {
		block_print(&longest_chain[i].b, stdout);
	}

	/* Organize into a tree, check validity, and output balances. */
	/* TODO */

	struct balance *balances = NULL, *p, *next;
	/* Print out the list of balances. */
	for (p = balances; p != NULL; p = next) {
		next = p->next;
		printf("%s %d\n", byte32_to_hex(p->pubkey.x), p->balance);
		free(p);
	}

	free(blocks);
	free(blocknodes);
	return 0;
}
