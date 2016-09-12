#include <stdio.h>
#include <stdlib.h>

#include <parc/algol/parc_Object.h>
#include <parc/algol/parc_Buffer.h>
#include <parc/algol/parc_SafeMemory.h>
#include <parc/algol/parc_LinkedList.h>
#include <parc/developer/parc_StopWatch.h>

#include <parc/security/parc_CryptoHasher.h>
#include <parc/security/parc_SecureRandom.h>

#include "argon2.c"
#include "scrypt.c"
//#include "balloon.c"

#define NUM_TRIALS 1000

typedef struct {
    int length;
    double averageTime;
} StatsEntry;

static bool
_statsEntry_Destructor(StatsEntry **statsPtr)
{
    return true;
}

parcObject_Override(StatsEntry, PARCObject,
                    .destructor = (PARCObjectDestructor *) _statsEntry_Destructor);

parcObject_ImplementAcquire(statsEntry, StatsEntry);
parcObject_ImplementRelease(statsEntry, StatsEntry);

StatsEntry *
statsEntry_Create(int n, double time)
{
    StatsEntry *entry = parcObject_CreateInstance(StatsEntry);
    entry->length = n;
    entry->averageTime = time;
    return entry;
}

void
usage(char *prog)
{
    fprintf(stderr, "%s <alg> <low> <high>", prog);
    // XXX: print the other parts of the message
}

PARCBuffer *
hashFunction(PARCCryptoHasher *instance, PARCBuffer *buffer)
{
    parcCryptoHasher_Init(instance);
    parcCryptoHasher_UpdateBuffer(instance, buffer);
    PARCCryptoHash *hash = parcCryptoHasher_Finalize(instance);
    PARCBuffer *digest = parcBuffer_Acquire(parcCryptoHash_GetDigest(hash));
    parcCryptoHash_Release(&hash);
    return digest;
}

PARCLinkedList *
profileObfuscationFunction(PARCCryptoHasher *hasher, int low, int high)
{
    PARCLinkedList *results = parcLinkedList_Create();

    PARCSecureRandom *random = parcSecureRandom_Create();

    // Compute an average time for each input size
    for (int i = low; i <= high; i++) {
        // Compute an average value for this one entry
        PARCStopwatch *timer = parcStopwatch_Create();
        parcStopwatch_Start(timer);
        uint64_t totalTime = 0;
        for (int t = 0; t < NUM_TRIALS; t++) {
            // Generate the input buffer to be hashed
            PARCBuffer *input = parcBuffer_Allocate(i);
            parcSecureRandom_NextBytes(random, input);
            //fprintf(stderr, "Hashing %d %d\n", i, t);

            // Compute the hash of the input
            uint64_t startTime = parcStopwatch_ElapsedTimeNanos(timer);
            PARCBuffer *output = hashFunction(hasher, input);
            uint64_t endTime = parcStopwatch_ElapsedTimeNanos(timer);
            totalTime += (endTime - startTime);

            parcBuffer_Release(&output);
            parcBuffer_Release(&input);
        }
        parcStopwatch_Release(&timer);

        // Append the results
        double average = ((double) totalTime) / NUM_TRIALS;
        StatsEntry *entry = statsEntry_Create(i, average);
        parcLinkedList_Append(results, entry);
    }

    return results;
}

void
processResults(char *alg, PARCLinkedList *results)
{
    PARCIterator *iterator = parcLinkedList_CreateIterator(results);
    while (parcIterator_HasNext(iterator)) {
        StatsEntry *entry = (StatsEntry *) parcIterator_Next(iterator);
        printf("%s,%d,%f\n", alg, entry->length, entry->averageTime);
    }
}

int 
main(int argc, char **argv)
{
    if (argc < 4) {
        usage(argv[0]);
        exit(-1);
    }

    // extract the parameters
    char *alg = argv[1];
    int low = atoi(argv[2]);
    int high = atoi(argv[3]);

    // Create the statically allocated hashers
    PARCCryptoHasher *sha256Hasher = parcCryptoHasher_Create(PARCCryptoHashType_SHA256);
    PARCCryptoHasher *argon2Hasher = parcCryptoHasher_CustomHasher(0, functor_argon2);
    PARCCryptoHasher *scryptHasher = parcCryptoHasher_CustomHasher(0, functor_scrypt);

    // switch on the algorithm
    PARCCryptoHasher *hasher;
    if (strcmp(alg, "SHA256") == 0) {
        hasher = sha256Hasher;
    } else if (strcmp(alg, "ARGON2") == 0) {
        hasher = argon2Hasher;
    } else if (strcmp(alg, "scrypt") == 0) {
        hasher = scryptHasher;
    } else {
        usage(argv[0]);
        exit(-2);
    }

    PARCLinkedList *results = profileObfuscationFunction(hasher, low, high);
    processResults(alg, results);
}

