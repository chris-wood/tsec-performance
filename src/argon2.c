#include <argon2.h>
#include <sodium/crypto_pwhash.h>

#include <parc/algol/parc_Buffer.h>
#include <parc/security/parc_SecureRandom.h>
#include <parc/security/parc_CryptoHasher.h>

int argon2TCost;
int argon2MCost;
int argon2DCost;

void
argon2_init()
{
    argon2TCost = crypto_pwhash_OPSLIMIT_MODERATE;
    argon2MCost = crypto_pwhash_MEMLIMIT_MODERATE;
}

typedef struct {
    int hashLength;
    int saltLength;
    uint32_t tCost;
    uint32_t mCost;
    uint32_t parallelism;

    PARCBuffer *outputBuffer;
    PARCBuffer *saltBuffer;
    PARCSecureRandom *rng;
} Argon2Hasher;

static bool
_argon2Hasher_Destructor(Argon2Hasher **hasherPtr)
{
    Argon2Hasher *hasher = *hasherPtr;
    if (hasher->outputBuffer != NULL) {
        parcBuffer_Release(&hasher->outputBuffer);
    }
    if (hasher->saltBuffer != NULL) {
        parcBuffer_Release(&hasher->saltBuffer);
    }
    parcSecureRandom_Release(&hasher->rng);
    return true;
}

parcObject_Override(Argon2Hasher, PARCObject,
    .destructor = (PARCObjectDestructor *) _argon2Hasher_Destructor);

Argon2Hasher *
argon2Hasher_Create(void *env)
{
    Argon2Hasher *hasher = parcObject_CreateInstance(Argon2Hasher);
    if (hasher != NULL) {
        hasher->hashLength = 32;
        hasher->saltLength = 16;
        hasher->tCost = argon2TCost;
        hasher->mCost = argon2MCost;
        hasher->parallelism = argon2DCost;
        hasher->rng = parcSecureRandom_Create();
        hasher->outputBuffer = NULL;
        hasher->saltBuffer = NULL;
    }
    return hasher;
}

Argon2Hasher *
argon2Hasher_2_8_Create(void *env)
{
    Argon2Hasher *hasher = parcObject_CreateInstance(Argon2Hasher);
    if (hasher != NULL) {
        hasher->hashLength = 32;
        hasher->saltLength = 16;
        hasher->tCost = 2;
        hasher->mCost = 8;
        hasher->parallelism = 1;
        hasher->rng = parcSecureRandom_Create();
        hasher->outputBuffer = NULL;
        hasher->saltBuffer = NULL;
    }
    return hasher;
}

int
argon2Hasher_Init(Argon2Hasher *hasher)
{
    if (hasher->outputBuffer != NULL) {
        parcBuffer_Release(&hasher->outputBuffer);
    }
    if (hasher->saltBuffer != NULL) {
        parcBuffer_Release(&hasher->saltBuffer);
    }

    hasher->outputBuffer = parcBuffer_Allocate(hasher->hashLength);
    hasher->saltBuffer = parcBuffer_Allocate(hasher->saltLength);
    parcSecureRandom_NextBytes(hasher->rng, hasher->saltBuffer);

    return 0;
}

int
argon2Hasher_Update(Argon2Hasher *hasher, const void *buffer, size_t length)
{
    char *salt = parcBuffer_Overlay(hasher->saltBuffer, 0);
    char *hash = parcBuffer_Overlay(hasher->outputBuffer, 0);
    argon2i_hash_raw(hasher->tCost, hasher->mCost, hasher->parallelism, buffer, length, salt, hasher->saltLength, hash, hasher->hashLength);
    return length;
}

PARCBuffer *
argon2Hasher_Finalize(Argon2Hasher *hasher)
{
    return parcBuffer_Acquire(hasher->outputBuffer);
}

static PARCCryptoHasherInterface functor_argon2 = {
    .functor_env = NULL,
    .hasher_setup = (void *(*)(void *)) argon2Hasher_Create, // create before wrapping
    .hasher_init = (int (*)(void *)) argon2Hasher_Init,
    .hasher_update = (int (*)(void *, const void *, size_t)) argon2Hasher_Update,
    .hasher_finalize = (PARCBuffer *(*)(void *)) argon2Hasher_Finalize,
    .hasher_destroy = (void  (*)(void **)) _argon2Hasher_Destructor
};

static PARCCryptoHasherInterface functor_argon2_2_8 = {
    .functor_env = NULL,
    .hasher_setup = (void *(*)(void *)) argon2Hasher_2_8_Create, // create before wrapping
    .hasher_init = (int (*)(void *)) argon2Hasher_Init,
    .hasher_update = (int (*)(void *, const void *, size_t)) argon2Hasher_Update,
    .hasher_finalize = (PARCBuffer *(*)(void *)) argon2Hasher_Finalize,
    .hasher_destroy = (void  (*)(void **)) _argon2Hasher_Destructor
};
