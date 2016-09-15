#include <parc/algol/parc_Buffer.h>
#include <parc/security/parc_CryptoHasher.h>

#ifdef __APPLE__
#include <CommonCrypto/CommonDigest.h>

#define CTX_SHA256    CC_SHA256_CTX
#define INIT_SHA256   CC_SHA256_Init
#define UPDATE_SHA256 CC_SHA256_Update
#define FINAL_SHA256  CC_SHA256_Final
#define LENGTH_SHA256 CC_SHA256_DIGEST_LENGTH

#define CTX_SHA512    CC_SHA512_CTX
#define INIT_SHA512   CC_SHA512_Init
#define UPDATE_SHA512 CC_SHA512_Update
#define FINAL_SHA512  CC_SHA512_Final
#define LENGTH_SHA512 CC_SHA512_DIGEST_LENGTH

#else
#include <openssl/sha.h>
#define CTX_SHA256    SHA256_CTX
#define INIT_SHA256   SHA256_Init
#define UPDATE_SHA256 SHA256_Update
#define FINAL_SHA256  SHA256_Final
#define LENGTH_SHA256 SHA256_DIGEST_LENGTH

#define CTX_SHA512    SHA512_CTX
#define INIT_SHA512   SHA512_Init
#define UPDATE_SHA512 SHA512_Update
#define FINAL_SHA512  SHA512_Final
#define LENGTH_SHA512 SHA512_DIGEST_LENGTH
#endif

typedef struct {
    PARCBuffer *outputBuffer;
    void *ctx;
} SHA2562Hasher;

static bool
_sha256Hasher_Destructor(SHA2562Hasher **hasherPtr)
{
    SHA2562Hasher *hasher = *hasherPtr;
    if (hasher->outputBuffer != NULL) {
        parcBuffer_Release(&hasher->outputBuffer);
    }
    return true; 
}

parcObject_Override(SHA2562Hasher, PARCObject,
    .destructor = (PARCObjectDestructor *) _sha256Hasher_Destructor);

SHA2562Hasher *
sha256Hasher_Create(void *env)
{
    SHA2562Hasher *hasher = parcObject_CreateInstance(Argon2Hasher);
    if (hasher != NULL) {
        hasher->outputBuffer = NULL;
        hasher->ctx = parcMemory_AllocateAndClear(sizeof(CTX_SHA256));
    }
    return hasher;
}

int
sha256Hasher_Init(SHA2562Hasher *hasher)
{
    if (hasher->outputBuffer != NULL) {
        parcBuffer_Release(&hasher->outputBuffer);
    }
    hasher->outputBuffer = parcBuffer_Allocate(LENGTH_SHA256);
    return INIT_SHA256(hasher->ctx);
}

int
sha256Hasher_Update(SHA2562Hasher *hasher, const void *buffer, size_t length)
{
    return UPDATE_SHA256(hasher->ctx, buffer, (unsigned) length);
}

PARCBuffer *
sha256Hasher_Finalize(SHA2562Hasher *hasher)
{
    FINAL_SHA256(parcBuffer_Overlay(hasher->outputBuffer, 0), hasher->ctx);
    return parcBuffer_Acquire(hasher->outputBuffer);
}

static PARCCryptoHasherInterface functor_sha256 = {
    .functor_env = NULL,
    .hasher_setup = (void *(*)(void *)) sha256Hasher_Create, // create before wrapping
    .hasher_init = (int (*)(void *)) sha256Hasher_Init,
    .hasher_update = (int (*)(void *, const void *, size_t)) sha256Hasher_Update,
    .hasher_finalize = (PARCBuffer *(*)(void *)) sha256Hasher_Finalize,
    .hasher_destroy = (void  (*)(void **)) _sha256Hasher_Destructor
};

