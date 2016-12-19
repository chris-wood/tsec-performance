#include <libscrypt.h>

#include <parc/algol/parc_Buffer.h>
#include <parc/security/parc_SecureRandom.h>
#include <parc/security/parc_CryptoHasher.h>

int scrypt_N = (1 << 14);
int scrypt_r = 8;
int scrypt_p = 1;

typedef struct {
    int hashLength;
    int saltLength;

    uint32_t N;
    uint32_t r;
    uint32_t p;

    PARCBuffer *outputBuffer;
    PARCBuffer *saltBuffer;
    PARCSecureRandom *rng;
} scryptHasher;

static bool
_scryptHasher_Destructor(scryptHasher **hasherPtr)
{
    scryptHasher *hasher = *hasherPtr;
    if (hasher->outputBuffer != NULL) {
        parcBuffer_Release(&hasher->outputBuffer);
    }
    if (hasher->saltBuffer != NULL) {
        parcBuffer_Release(&hasher->saltBuffer);
    }
    parcSecureRandom_Release(&hasher->rng);
    return true;
}

parcObject_Override(scryptHasher, PARCObject,
    .destructor = (PARCObjectDestructor *) _scryptHasher_Destructor);

scryptHasher *
scryptHasher_Create(void *env)
{
    scryptHasher *hasher = parcObject_CreateInstance(Argon2Hasher);
    if (hasher != NULL) {
        hasher->hashLength = 32;
        hasher->saltLength = 16;

        hasher->N = scrypt_N;
        hasher->r = scrypt_r;
        hasher->p = scrypt_p;

        hasher->rng = parcSecureRandom_Create();
        hasher->outputBuffer = NULL;
        hasher->saltBuffer = NULL;
    }
    return hasher;
}

int
scryptHasher_Init(scryptHasher *hasher)
{
    if (hasher->outputBuffer != NULL) {
        parcBuffer_Release(&hasher->outputBuffer);
    }
    if (hasher->saltBuffer != NULL) {
        parcBuffer_Release(&hasher->saltBuffer);
    }

    hasher->outputBuffer = parcBuffer_Allocate(hasher->hashLength);
    hasher->saltBuffer = parcBuffer_Allocate(hasher->saltLength);

    return 0;
}

// http://stackoverflow.com/questions/11126315/what-are-optimal-scrypt-work-factors
// make LDFLAGS= CFLAGS_EXTRA=
int
scryptHasher_Update(scryptHasher *hasher, const void *buffer, size_t length)
{
    const uint8_t *salt = parcBuffer_Overlay(hasher->saltBuffer, 0);
    uint8_t *hash = parcBuffer_Overlay(hasher->outputBuffer, 0);
    int result = libscrypt_scrypt(buffer, length, salt, hasher->saltLength, SCRYPT_N,
                SCRYPT_r, SCRYPT_p, hash, hasher->hashLength);
    return result;
}

PARCBuffer *
scryptHasher_Finalize(scryptHasher *hasher)
{
    return parcBuffer_Acquire(hasher->outputBuffer);
}

static PARCCryptoHasherInterface functor_scrypt = {
    .functor_env = NULL,
    .hasher_setup = (void *(*)(void *)) scryptHasher_Create, // create before wrapping
    .hasher_init = (int (*)(void *)) scryptHasher_Init,
    .hasher_update = (int (*)(void *, const void *, size_t)) scryptHasher_Update,
    .hasher_finalize = (PARCBuffer *(*)(void *)) scryptHasher_Finalize,
    .hasher_destroy = (void  (*)(void **)) _scryptHasher_Destructor
};
