#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <parc/algol/parc_Object.h>
#include <parc/algol/parc_Buffer.h>
#include <parc/algol/parc_SafeMemory.h>
#include <parc/algol/parc_LinkedList.h>
#include <parc/developer/parc_Stopwatch.h>

#include <parc/security/parc_CryptoHasher.h>
#include <parc/security/parc_SecureRandom.h>

#include "argon2.c"
#include "scrypt.c"
#include "sha256.c"

#define NUM_TRIALS 100

// call this function to start a nanosecond-resolution timer
struct timespec timer_start() {
    struct timespec start_time;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start_time);
    return start_time;
}

// call this function to end a timer, returning nanoseconds elapsed as a long
long timer_end(struct timespec start_time){
    struct timespec end_time;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end_time);
    long diffInNanos = end_time.tv_nsec - start_time.tv_nsec;
    return diffInNanos;
}

void
usage(char *prog)
{
    fprintf(stderr, "%s <alg> (params)", prog);
}

PARCBuffer *
hashFunction(PARCCryptoHasher *instance, PARCBuffer *buffer)
{
    parcCryptoHasher_UpdateBuffer(instance, buffer);
    PARCCryptoHash *hash = parcCryptoHasher_Finalize(instance);
    PARCBuffer *digest = parcBuffer_Acquire(parcCryptoHash_GetDigest(hash));
    parcCryptoHash_Release(&hash);
    return digest;
}

double
profile(PARCCryptoHasher *hasher)
{
    int t;
    PARCSecureRandom *random = parcSecureRandom_Create();

    // Compute an average value for this one entry
    PARCStopwatch *timer = parcStopwatch_Create();
    parcStopwatch_Start(timer);
    uint64_t totalTime = 0;
    for (t = 0; t < NUM_TRIALS; t++) {
        // Generate the input buffer to be hashed
        PARCBuffer *input = parcBuffer_Allocate(32);
        parcSecureRandom_NextBytes(random, input);
        parcCryptoHasher_Init(hasher);

        // Compute the hash of the input
        uint64_t startTime = parcStopwatch_ElapsedTimeNanos(timer);
        struct timespec start = timer_start();
        PARCBuffer *output = hashFunction(hasher, input);
        long elapsed = timer_end(start);
        uint64_t endTime = parcStopwatch_ElapsedTimeNanos(timer);
        
        totalTime += (endTime - startTime);

        printf("%lu\n", elapsed);

        parcBuffer_Release(&output);
        parcBuffer_Release(&input);
    }
    parcStopwatch_Release(&timer);

    // Append the results
    double average = ((double) totalTime) / NUM_TRIALS;
    return average;
}

int 
main(int argc, char **argv)
{
    int i;
    if (argc < 2) {
        for (i = 0; i < argc; i++) {
            printf("%s ", argv[i]);
        }
        usage(argv[0]);
        exit(-1);
    }

    argon2_init();

    // extract the parameters
    char *alg = argv[1];

    // switch on the algorithm
    PARCCryptoHasher *hasher;
    if (strcmp(alg, "SHA256") == 0) {
        PARCCryptoHasher *sha256Hasher = parcCryptoHasher_CustomHasher(0, functor_sha256);
        hasher = sha256Hasher;
        double time = profile(sha256Hasher);
        printf("%f\n", time);
    } else if (strcmp(alg, "ARGON2") == 0) {
        //argon2TCost = atoi(argv[2]);
        //argon2MCost = atoi(argv[3]);
        //argon2DCost = atoi(argv[4]);
        PARCCryptoHasher *argon2Hasher = parcCryptoHasher_CustomHasher(0, functor_argon2);
        double time = profile(argon2Hasher);
        printf("%f\n", time);
    } else if (strcmp(alg, "scrypt") == 0) {
        //scrypt_N = atoi(argv[2]);
        //scrypt_r = atoi(argv[3]);
        //scrypt_p = atoi(argv[4]);
        PARCCryptoHasher *scryptHasher = parcCryptoHasher_CustomHasher(0, functor_scrypt);
        double time = profile(scryptHasher);
        printf("%f\n", time);
    } else {
        for (i = 0; i < argc; i++) {
            printf("%s ", argv[i]);
        }
        usage(argv[0]);
        exit(-2);
    }
}

