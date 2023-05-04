-type cipher_iv() :: aes_128_cbc
                   | aes_192_cbc
                   | aes_256_cbc
                   | aes_cbc

                   | aes_128_ofb
                   | aes_192_ofb
                   | aes_256_ofb

                   | aes_128_cfb128
                   | aes_192_cfb128
                   | aes_256_cfb128
                   | aes_cfb128

                   | aes_128_cfb8
                   | aes_192_cfb8
                   | aes_256_cfb8
                   | aes_cfb8

                   | aes_128_ctr
                   | aes_192_ctr
                   | aes_256_ctr
                   | aes_ctr

                   | blowfish_cbc
                   | blowfish_cfb64
                   | blowfish_ofb64
                   | chacha20
                   | des_ede3_cbc
                   | des_ede3_cfb

                   | des_cbc
                   | des_cfb
                   | rc2_cbc .


-type sha3() :: sha3_224 | sha3_256 | sha3_384 | sha3_512 .
-type sha3_xof() :: shake128 | shake256 .
-type blake2() :: blake2b | blake2s .
-type compatibility_only_hash() :: md5 | md4 .
-type hash_algorithm() :: crypto:sha1() | crypto:sha2() | sha3() | sha3_xof() | blake2() | ripemd160 | compatibility_only_hash() .

