#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include "common.h"

/* Usage: genkey FILENAME
 * Generate a key and write it to the file FILENAME. */

/* Interpret the 256 bits in buf as a private key and return an EC_KEY *. */
static EC_KEY *generate_key_from_buffer(const unsigned char buf[32])
{
	EC_KEY *key;
	BIGNUM *bn;
	int rc;

	key = NULL;
	bn = NULL;

	key = EC_KEY_new_by_curve_name(EC_GROUP_NID);
	if (key == NULL)
		goto err;

	bn = BN_bin2bn(buf, 32, NULL);
	if (bn == NULL)
		goto err;

	rc = EC_KEY_set_private_key(key, bn);

	if (rc != 1)
		goto err;

	BN_free(bn);

	return key;

err:
	if (key != NULL)
		EC_KEY_free(key);
	if (bn != NULL)
		BN_free(bn);
	return NULL;
}

static EC_KEY *generate_public_key_from_buffer(void) {
	EC_KEY *key;
	BIGNUM *bn;

	key = EC_KEY_new_by_curve_name(EC_GROUP_NID);
	if (key == NULL) {
		goto err;
	}

	//BUFFER
	unsigned char buf[32];
	int i;
	srand(1234);
	for (i = 0; i < 32; i++) {
		buf[i] = rand() & 0xff;
	}
	printf("HIIIIII %c\n", buf[1]);
	
	bn = BN_bin2bn(buf, 32, NULL);

	if (bn == NULL)
		goto err;

	int rc = EC_KEY_set_private_key(key, bn);

	if (rc != 1)
		goto err;

	//PUBLIC KEY STUFF
	EC_POINT *pubkey;
	pubkey = EC_POINT_new(EC_KEY_get0_group(key));

	if (pubkey == NULL) {
		EC_KEY_free(key);
		return NULL;
	}
	if (EC_POINT_mul(EC_KEY_get0_group(key), pubkey,
		EC_KEY_get0_private_key(key), NULL, NULL, NULL) != 1) {
		EC_POINT_free(pubkey);
		EC_KEY_free(key);
		return NULL;
	}
	if (EC_KEY_set_public_key(key, pubkey) != 1) {
		EC_POINT_free(pubkey);
		EC_KEY_free(key);
		return NULL;
	}
	EC_POINT_free(pubkey);

	//Print Key
	EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(EC_GROUP_NID);

	EC_KEY_set_group(key, ec_group);

	const EC_POINT *pub = EC_KEY_get0_public_key(key);

	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();

	if (EC_POINT_get_affine_coordinates_GFp(ec_group, pub, x, y, NULL)) {
		BN_print_fp(stdout, x);
		putc('\n', stdout);
		BN_print_fp(stdout, y);
		putc('\n', stdout);
	}	

	return key;

err:
	if (key != NULL)
		EC_KEY_free(key);
	if (bn != NULL)
		BN_free(bn);
	return NULL;
}

static EC_KEY *generate_public_key_from_time(void) {
	EC_KEY *key;
	int valid = 0;
	time_t tim = 1443700800;
	while (valid == 0) {
		key = EC_KEY_new_by_curve_name(EC_GROUP_NID);
		if (key == NULL) {
			return NULL;
		}

		//BUFFER
		unsigned char buf[32];
		int i;
		
		// printf("TIME: %lld\n", (long long)tim);
		srand(tim);
		for (i = 0; i < 32; i++) {
			buf[i] = rand() & 0xff;
		}
		tim += 1;

		BIGNUM *bn;
		bn = BN_bin2bn(buf, 32, NULL);

		if (bn == NULL)
			return NULL;

		int rc = EC_KEY_set_private_key(key, bn);

		if (rc != 1)
			return NULL;

		//PUBLIC KEY STUFF
		EC_POINT *pubkey;
		pubkey = EC_POINT_new(EC_KEY_get0_group(key));

		if (pubkey == NULL) {
			EC_KEY_free(key);
			return NULL;
		}
		if (EC_POINT_mul(EC_KEY_get0_group(key), pubkey,
			EC_KEY_get0_private_key(key), NULL, NULL, NULL) != 1) {
			EC_POINT_free(pubkey);
			EC_KEY_free(key);
			return NULL;
		}
		if (EC_KEY_set_public_key(key, pubkey) != 1) {
			EC_POINT_free(pubkey);
			EC_KEY_free(key);
			return NULL;
		}
		EC_POINT_free(pubkey);

		//Print Key
		EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(EC_GROUP_NID);

		EC_KEY_set_group(key, ec_group);

		const EC_POINT *pub = EC_KEY_get0_public_key(key);

		BIGNUM *x = BN_new();
		BIGNUM *y = BN_new();

		if (EC_POINT_get_affine_coordinates_GFp(ec_group, pub, x, y, NULL)) {

			BIGNUM *dest_x = BN_new();
			//bd63383861d845b62637f221ca3b4cc21d1f82d5c0e018b8f2fc2906702c4f1b
			BN_hex2bn(&dest_x, "bd63383861d845b62637f221ca3b4cc21d1f82d5c0e018b8f2fc2906702c4f1b");
			// BIGNUM *dest_y = BN_new();
			//17e6cb83581672fd7d690c5416a50d2a0aaf3d9ea961761ab7000140bea78218
			
			if (BN_cmp(x, dest_x) == 0) {
				valid = 1;
				BN_print_fp(stdout, x);
				putc('\n', stdout);
				BN_print_fp(stdout, y);
				putc('\n', stdout);
			}
		}	

	}

	return key;
}

/* Generate a key using EC_KEY_generate_key. */
static EC_KEY *generate_key(void)
{
	EC_KEY *key;
	int rc;

	key = EC_KEY_new_by_curve_name(EC_GROUP_NID);
	if (key == NULL)
		return NULL;

	rc = EC_KEY_generate_key(key);

	if (rc != 1) {
		EC_KEY_free(key);
		return NULL;
	}

	return key;
}


int main(int argc, char *argv[])
{
	const char *filename;
	EC_KEY *key;
	int rc;

	if (argc != 2) {
		fprintf(stderr, "need an output filename\n");
		exit(1);
	}

	filename = argv[1];

	//key = generate_key();
	//key = generate_key_from_buffer(buf);
	// key = generate_public_key_from_buffer();
	key = generate_public_key_from_time();

	// BIGNUM *dest_x = BN_new();
	// BN_hex2bn(&dest_x, "bd63383861d845b62637f221ca3b4cc21d1f82d5c0e018b8f2fc2906702c4f1b");
	// BN_print_fp(stdout, dest_x);

	if (key == NULL) {
		fprintf(stderr, "error generating key\n");
		exit(1);
	}

	rc = key_write_filename(filename, key);
	if (rc != 1) {
		fprintf(stderr, "error saving key\n");
		exit(1);
	}

	EC_KEY_free(key);

	return 0;
}
