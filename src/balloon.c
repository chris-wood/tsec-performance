#include <balloon.h>

#include <parc/algol/parc_Buffer.h>
#include <parc/security/parc_SecureRandom.h>
#include <parc/security/parc_CryptoHasher.h>

typedef struct {
    int hashLength;
    int saltLength;
    struct balloon_options options;
    PARCBuffer *outputBuffer;
    PARCBuffer *saltBuffer;
} balloonHasher;

static bool
_balloonHasher_Destructor(balloonHasher **hasherPtr)
{
    balloonHasher *hasher = *hasherPtr;
    if (hasher->outputBuffer != NULL) {
        parcBuffer_Release(&hasher->outputBuffer);
    }
    if (hasher->saltBuffer != NULL) {
        parcBuffer_Release(&hasher->saltBuffer);
    }
    return true; 
}

parcObject_Override(balloonHasher, PARCObject,
    .destructor = (PARCObjectDestructor *) _balloonHasher_Destructor);

balloonHasher *
balloonHasher_Create(void *env)
{
    balloonHasher *hasher = parcObject_CreateInstance(Argon2Hasher);
    if (hasher != NULL) {
        hasher->hashLength = 32;
        hasher->saltLength = 16;

        struct comp_options comp_opts = {
            .comp = COMP__BLAKE_2B,
            .comb = COMB__HASH
        };

        hasher->options.m_cost = 0;
        hasher->options.t_cost = 0;
        hasher->options.n_neighbors = 0;
        hasher->options.n_threads = 0;
        hasher->options.comp_opts = comp_opts;
        hasher->options.mix = MIX__BALLOON_SINGLE_BUFFER;

        hasher->outputBuffer = NULL;
        hasher->saltBuffer = NULL;
    }
    return hasher;
}

int
balloonHasher_Init(scryptHasher *hasher)
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

// http://stackoverflow.com/questions/11126315/what-are-optimal-balloon-work-factors
int
balloonHasher_Update(balloonHasher *hasher, const void *buffer, size_t length)
{
    const uint8_t *salt = parcBuffer_Overlay(hasher->saltBuffer, 0);
    uint8_t *hash = parcBuffer_Overlay(hasher->outputBuffer, 0);

    // XXX: compute the hash
    int error = BalloonHash(hash, hasher->hashLength, buffer, length, salt, hasher->saltLength, &hasher->options);

    return error;
}

PARCBuffer *
balloonHasher_Finalize(scryptHasher *hasher)
{
    return parcBuffer_Acquire(hasher->outputBuffer);
}

static PARCCryptoHasherInterface functor_balloon = {
    .functor_env = NULL,
    .hasher_setup = (void *(*)(void *)) balloonHasher_Create, // create before wrapping
    .hasher_init = (int (*)(void *)) balloonHasher_Init,
    .hasher_update = (int (*)(void *, const void *, size_t)) balloonHasher_Update,
    .hasher_finalize = (PARCBuffer *(*)(void *)) balloonHasher_Finalize,
    .hasher_destroy = (void  (*)(void **)) _balloonHasher_Destructor
};
