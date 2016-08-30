#include <parc/algol/parc_SafeMemory.h>
#include <parc/algol/parc_BufferComposer.h>
#include <parc/algol/parc_LinkedList.h>
#include <parc/algol/parc_Iterator.h>
#include <parc/algol/parc_HashMap.h>

#include <parc/developer/parc_StopWatch.h>
#include <parc/statistics/parc_BasicStats.h>
#include <parc/security/parc_SecureRandom.h>

#include <ccnx/common/ccnx_Name.h>
#include <ccnx/common/codec/ccnxCodec_TlvEncoder.h>
#include <ccnx/common/codec/schema_v1/ccnxCodecSchemaV1_Types.h>
#include <ccnx/common/codec/schema_v1/ccnxCodecSchemaV1_NameCodec.h>

#include <stdio.h>
#include <ctype.h>

#include <openssl/evp.h>
#include <sodium.h>

typedef struct {
    PARCBuffer *ciphertext;
    PARCBuffer *tag;
    PARCBuffer *IV;
} CiphertextTag;

int
peekFile(FILE *fp)
{
    int c = fgetc(fp);
    ungetc(c, fp);
    return c;
}

static PARCSecureRandom *rng; 

PARCBufferComposer *
readLine(FILE *fp)
{
    PARCBufferComposer *composer = parcBufferComposer_Create();
    char curr = fgetc(fp);
    while ((isalnum(curr) || curr == ':' || curr == '/' || curr == '.' || 
            curr == '_' || curr == '(' || curr == ')' || curr == '[' ||
            curr == ']' || curr == '-' || curr == '%' || curr == '+' ||
            curr == '=' || curr == ';' || curr == '$' || curr == '\'') && curr != EOF) {
        parcBufferComposer_PutChar(composer, curr);
        curr = fgetc(fp);
    }
    return composer;
}

static PARCBuffer *
_encodeName(CCNxName *name)
{
    CCNxCodecTlvEncoder *encoder = ccnxCodecTlvEncoder_Create();
    size_t length = ccnxCodecSchemaV1NameCodec_Encode(encoder, CCNxCodecSchemaV1Types_CCNxMessage_Name, name);
    PARCBuffer *container = ccnxCodecTlvEncoder_CreateBuffer(encoder);
    ccnxCodecTlvEncoder_Destroy(&encoder);
    return container;
}

static PARCBuffer *
_hashBuffer(PARCBuffer *buffer)
{
    PARCCryptoHasher *hasher = parcCryptoHasher_Create(PARCCryptoHashType_SHA256);
    parcCryptoHasher_Init(hasher);
    parcCryptoHasher_UpdateBuffer(hasher, buffer);
    PARCCryptoHash *hash = parcCryptoHasher_Finalize(hasher);

    PARCBuffer *digest = parcBuffer_Acquire(parcCryptoHash_GetDigest(hash));

    parcCryptoHash_Release(&hash);
    parcCryptoHasher_Release(&hasher);

    return digest;
}

// XXX: encode names using the codec, create TLV from the buffer, use TLV to create final name

static PARCBuffer *
_obfuscateName(PARCBuffer *encodedName)
{
    CCNxCodecTlvDecoder *decoder = ccnxCodecTlvDecoder_Create(encodedName);
    size_t type = ccnxCodecTlvDecoder_GetType(decoder);
    size_t length = ccnxCodecTlvDecoder_GetLength(decoder);

    PARCBufferComposer *composer = parcBufferComposer_Create();
    PARCBufferComposer *fullComposer = parcBufferComposer_Create();
    parcBufferComposer_PutUint16(fullComposer, type);
    parcBufferComposer_PutUint16(fullComposer, 0); // need to fill in the length at the end

    size_t offset = 0;
    while (offset < length) {
        size_t innerType = ccnxCodecTlvDecoder_GetType(decoder);
        size_t innerLength = ccnxCodecTlvDecoder_GetLength(decoder);
        offset += innerLength + 4;

        // Extract and append the segment
        PARCBuffer *segmentValue = ccnxCodecTlvDecoder_GetValue(decoder, innerLength);
        parcBufferComposer_PutBuffer(composer, segmentValue);

        // Compute the hash of the segment
        PARCBuffer *prefixBuffer = parcBufferComposer_CreateBuffer(composer);
        PARCBuffer *digest = _hashBuffer(prefixBuffer);

        // Add the hashed segment to the new name
        parcBufferComposer_PutUint16(fullComposer, innerType);
        parcBufferComposer_PutUint16(fullComposer, parcBuffer_Remaining(digest));
        parcBufferComposer_PutBuffer(fullComposer, digest);

        // Free up memory
        parcBuffer_Release(&digest);
        parcBuffer_Release(&prefixBuffer);
        parcBuffer_Release(&segmentValue);
    }

    PARCBuffer *finalName = parcBufferComposer_ProduceBuffer(fullComposer);
    parcBufferComposer_Release(&fullComposer);
    parcBufferComposer_Release(&composer);
    ccnxCodecTlvDecoder_Destroy(&decoder);

    // XXX: need to go back and reset the name

    return finalName;
}

static PARCBuffer *
_reverseName(PARCHashMap *table, PARCBuffer *buffer)
{
    return (PARCBuffer *) parcHashMap_Get(table, buffer);
}

static CiphertextTag *
_sealPlaintext(PARCBuffer *plaintext, PARCBuffer *IV, PARCBuffer *keyBuffer)
{
    size_t plaintextLength = parcBuffer_Remaining(plaintext);
    size_t ciphertextLength = plaintextLength + crypto_aead_chacha20poly1305_ABYTES;

    PARCBuffer *ciphertext = parcBuffer_Allocate(ciphertextLength);
    uint8_t *ciphertextArray = parcBuffer_Overlay(ciphertext, 0);
    uint8_t *plaintextArray = parcBuffer_Overlay(plaintext, 0);

    uint8_t *nonce = parcBuffer_Overlay(IV, 0);
    uint8_t *key = parcBuffer_Overlay(keyBuffer, 0);

    // XXX: maybe add packet metadata as AAD later
    uint8_t *aad = NULL;
    size_t aadLength = 0;

    size_t tagLength = crypto_aead_chacha20poly1305_ABYTES;
    PARCBuffer *tagBuffer = parcBuffer_Allocate(tagLength);
    uint8_t *tag = parcBuffer_Overlay(tagBuffer, 0);

    // Perform encryption
    size_t validationLength = 0;
    int result = crypto_aead_chacha20poly1305_encrypt_detached(ciphertextArray, tag,
                                                        (unsigned long long *) &validationLength, plaintextArray,
                                                        plaintextLength, aad, aadLength,
                                                        NULL, nonce, key);
    if (result != 0) {
        parcBuffer_Release(&tagBuffer);
        parcBuffer_Release(&ciphertext);
        return NULL;
    }

    // Wrap the ciphertext
    PARCBuffer *ciphertextBuffer = parcBuffer_Allocate(plaintextLength);
    parcBuffer_PutArray(ciphertextBuffer, plaintextLength, ciphertextArray);
    parcBuffer_Flip(ciphertextBuffer);

    CiphertextTag *tuple = (CiphertextTag *) malloc(sizeof(CiphertextTag));
    tuple->ciphertext = parcBuffer_Acquire(ciphertextBuffer);
    tuple->tag = parcBuffer_Acquire(tagBuffer);
    tuple->IV = parcBuffer_Acquire(IV);

    parcBuffer_Release(&tagBuffer);
    parcBuffer_Release(&ciphertextBuffer);
    parcBuffer_Release(&ciphertext);

    return tuple;
}

static PARCBuffer *
_openCiphertext(PARCBuffer *ciphertextBuffer, PARCBuffer *tagBuffer, PARCBuffer *IV, PARCBuffer *keyBuffer)
{
    uint8_t *nonce = parcBuffer_Overlay(IV, 0);
    uint8_t *key = parcBuffer_Overlay(keyBuffer, 0);
    uint8_t *ciphertext = parcBuffer_Overlay(ciphertextBuffer, 0);
    uint8_t *tag = parcBuffer_Overlay(tagBuffer, 0);

    uint8_t *aad = NULL;
    size_t aadLength = 0;

    size_t ciphertextLength = parcBuffer_Remaining(ciphertextBuffer);
    PARCBuffer *plaintextBuffer = parcBuffer_Allocate(ciphertextLength);
    uint8_t *plaintext = parcBuffer_Overlay(plaintextBuffer, 0);

    int result = crypto_aead_chacha20poly1305_decrypt_detached(plaintext, NULL, ciphertext,
                                                        ciphertextLength, tag, aad,
                                                        aadLength, nonce, key);
    if (result != -1) {
        return plaintextBuffer;
    } else {
        parcBuffer_Release(&plaintextBuffer);
        return NULL;
    }
}

static PARCBuffer *
_deriveKeyFromName(PARCBuffer *nameBuffer)
{
    PARCBuffer *keyBuffer = parcBuffer_Allocate(32);

    PARCCryptoHasher *hasher = parcCryptoHasher_Create(PARCCryptoHashType_SHA256);
    parcCryptoHasher_Init(hasher);
    parcCryptoHasher_UpdateBuffer(hasher, nameBuffer);
    PARCCryptoHash *hashDigest = parcCryptoHasher_Finalize(hasher);
    PARCBuffer *nameDigest = parcCryptoHash_GetDigest(hashDigest);

    uint8_t *nameArray = parcByteArray_Array(parcBuffer_Array(nameDigest));
    size_t nameArrayLength = parcBuffer_Remaining(nameDigest);
    
    uint8_t *keyArray = parcByteArray_Array(parcBuffer_Array(keyBuffer));
    size_t keyLength = parcBuffer_Remaining(keyBuffer);
    
    uint8_t keyid[crypto_generichash_blake2b_SALTBYTES] = {0};
    uint8_t appid[crypto_generichash_blake2b_PERSONALBYTES] = {0};
    
    crypto_generichash_blake2b_salt_personal(keyArray, keyLength,
                                            NULL, 0,
                                            nameArray, nameArrayLength,
                                            keyid, appid);
    parcCryptoHash_Release(&hashDigest);
    
    return keyBuffer;
}

static PARCBuffer *
_createRandomBuffer(int size)
{
    PARCBuffer *buffer = parcBuffer_Allocate(size);
    parcSecureRandom_NextBytes(rng, buffer);
    return buffer;
}

static CiphertextTag *
_encryptContent(PARCBuffer *name, PARCBuffer *data)
{
    // 1. Derive the key from the name
    PARCBuffer *keyBuffer = _deriveKeyFromName(name);

    // 2. Generate a random IV
    PARCBuffer *IV = _createRandomBuffer(32);

    // 3. Encrypt the content
    CiphertextTag *output = _sealPlaintext(data, IV, keyBuffer);

    parcBuffer_Release(&keyBuffer);
    parcBuffer_Release(&IV);

    return output;
}

static PARCBuffer *
_decryptContent(PARCBuffer *name, CiphertextTag *tag)
{
    PARCBuffer *keyBuffer = _deriveKeyFromName(name);
    PARCBuffer *plaintext = _openCiphertext(tag->ciphertext, tag->tag, tag->IV, keyBuffer);
    return plaintext;
}

void
usage()
{
    fprintf(stderr, "usage: tsec_perf <uri_file> <n>\n");
    fprintf(stderr, "   - uri_file = A file that contains a list of CCNx URIs\n");
    fprintf(stderr, "   - n        = The maximum length prefix\n");
}

typedef struct {
    int numComponents;
    uint64_t obfuscateTime;
    uint64_t deobfuscateTime;
    uint64_t encryptTime;
    uint64_t decryptTime;
} TSecStatsEntry;

static bool
_tsecStatsEntry_Destructor(TSecStatsEntry **statsPtr)
{
    TSecStatsEntry *stats = *statsPtr;
    return true;
}

parcObject_Override(TSecStatsEntry, PARCObject,
                    .destructor = (PARCObjectDestructor *) _tsecStatsEntry_Destructor);

parcObject_ImplementAcquire(tsecStatsEntry, TSecStatsEntry);
parcObject_ImplementRelease(tsecStatsEntry, TSecStatsEntry);

TSecStatsEntry *
tsecStatsEntry_Create(int n)
{
    TSecStatsEntry *entry = parcObject_CreateInstance(TSecStatsEntry);
    entry->numComponents = n;
    return entry;
}

static void
displayStatsEntry(TSecStatsEntry *entry)
{
    printf("Obfuscate: %llu\n", entry->obfuscateTime);
    printf("Deobfuscate: %llu\n", entry->deobfuscateTime);
    printf("Encrypt: %llu\n", entry->encryptTime);
    printf("Decrypt: %llu\n", entry->decryptTime);
}

static void
displayTotalStats(PARCLinkedList *statList)
{
    PARCBasicStats *obfuscateStats = parcBasicStats_Create();
    PARCBasicStats *deobfuscateStats = parcBasicStats_Create();
    PARCBasicStats *encryptStats = parcBasicStats_Create();
    PARCBasicStats *decryptStats = parcBasicStats_Create();

    int N = 0;

    PARCIterator *itr = parcLinkedList_CreateIterator(statList);
    while (parcIterator_HasNext(itr)) {
        TSecStatsEntry *entry = (TSecStatsEntry *) parcIterator_Next(itr);
        N = entry->numComponents;
        
        parcBasicStats_Update(obfuscateStats, entry->obfuscateTime);
        parcBasicStats_Update(deobfuscateStats, entry->deobfuscateTime);
        parcBasicStats_Update(encryptStats, entry->encryptTime);
        parcBasicStats_Update(decryptStats, entry->decryptTime);
    }
    
    printf("%d,", N);
    printf("%f,%f,", parcBasicStats_Mean(obfuscateStats), parcBasicStats_StandardDeviation(obfuscateStats));
    printf("%f,%f,", parcBasicStats_Mean(deobfuscateStats), parcBasicStats_StandardDeviation(deobfuscateStats));
    printf("%f,%f,", parcBasicStats_Mean(encryptStats), parcBasicStats_StandardDeviation(encryptStats));
    printf("%f,%f\n", parcBasicStats_Mean(decryptStats), parcBasicStats_StandardDeviation(decryptStats));

    parcBasicStats_Release(&obfuscateStats);
    parcBasicStats_Release(&deobfuscateStats);
    parcBasicStats_Release(&encryptStats);
    parcBasicStats_Release(&decryptStats);
}

int
main(int argc, char **argv)
{
    if (argc != 3) {
        usage();
        exit(-1);
    }

    char *fname = argv[1];
    int N = atoi(argv[2]);

    FILE *file = fopen(fname, "r");
    if (file == NULL) {
        perror("Could not open file");
        usage();
        exit(-1);
    }

    // Create the FIB and list to hold all of the names
    PARCLinkedList *nameList = parcLinkedList_Create();

    int num = 0;
    int index = 0;
    do {
        PARCBufferComposer *composer = readLine(file);
        PARCBuffer *bufferString = parcBufferComposer_ProduceBuffer(composer);
        if (peekFile(file) == EOF) {
            break;
        }
        parcBufferComposer_Release(&composer);

        if (!parcBuffer_HasRemaining(bufferString)) {
            parcBuffer_Release(&bufferString);
            continue;
        }

        // Create the original name and store it for later
        //fprintf(stderr, "Parsing: %s\n", parcBuffer_ToString(bufferString));
        CCNxName *name = ccnxName_CreateFromBuffer(bufferString);
        parcBuffer_Release(&bufferString);
        if (name == NULL) {
            continue;
        }

        // Trim the name if necessary
        if (ccnxName_GetSegmentCount(name) > N) {
            size_t delta = ccnxName_GetSegmentCount(name) - N;
            name = ccnxName_Trim(name, delta);
        }

        // Debug display
        //char *nameString = ccnxName_ToString(name);
        //fprintf(stderr, "Read %d: %s\n", index, nameString);

        CCNxCodecTlvEncoder *encoder = ccnxCodecTlvEncoder_Create();
        ccnxCodecSchemaV1NameCodec_Encode(encoder, CCNxCodecSchemaV1Types_CCNxMessage_Name, name);
        ccnxCodecTlvEncoder_Finalize(encoder);
        PARCBuffer *encodedBuffer = ccnxCodecTlvEncoder_CreateBuffer(encoder);
        ccnxCodecTlvEncoder_Destroy(&encoder);
    
        parcLinkedList_Append(nameList, encodedBuffer);

        ccnxName_Release(&name);
        index++;
    } while (true);

    PARCLinkedList *stats = parcLinkedList_Create();
    PARCHashMap *table = parcHashMap_Create();
    rng = parcSecureRandom_Create();

    PARCIterator *iterator = parcLinkedList_CreateIterator(nameList);
    while (parcIterator_HasNext(iterator)) {

        PARCBuffer *nameBuffer = parcIterator_Next(iterator);

        PARCStopwatch *timer = parcStopwatch_Create();
        parcStopwatch_Start(timer);

        // 1. Obfuscation
        uint64_t startObfuscationTime = parcStopwatch_ElapsedTimeNanos(timer);
        PARCBuffer *obfuscatedName = _obfuscateName(nameBuffer);
        uint64_t endObfuscationTime = parcStopwatch_ElapsedTimeNanos(timer);

        // Save the mapping in the table (this is an offline step)
        parcHashMap_Put(table, obfuscatedName, nameBuffer);

        // 2. De-obfuscation
        uint64_t startDeobfuscationTime = parcStopwatch_ElapsedTimeNanos(timer);
        PARCBuffer *originalNameBuffer = _reverseName(table, obfuscatedName);
        uint64_t endDeobfuscationTime = parcStopwatch_ElapsedTimeNanos(timer);

        assertNotNull(originalNameBuffer, "Expected the original name to be retrieved");

        // 3. Encryption
        PARCBuffer *dataBuffer = _createRandomBuffer(1024);
        uint64_t startEncryptionTime = parcStopwatch_ElapsedTimeNanos(timer);
        CiphertextTag *ciphertext = _encryptContent(nameBuffer, dataBuffer);
        uint64_t endEncryptionTime = parcStopwatch_ElapsedTimeNanos(timer);

        // 4. Decryption
        uint64_t startDecryptionTime = parcStopwatch_ElapsedTimeNanos(timer);
        PARCBuffer *reverseName = _reverseName(table, obfuscatedName);
        PARCBuffer *plaintext = _decryptContent(nameBuffer, ciphertext);
        uint64_t endDecryptionTime = parcStopwatch_ElapsedTimeNanos(timer);

        assertTrue(parcBuffer_Equals(originalNameBuffer, reverseName), "Expected name retrieval to succeed");
        assertTrue(parcBuffer_Equals(plaintext, dataBuffer), "Expected decryption to succeed");

        parcBuffer_Release(&dataBuffer);
        parcBuffer_Release(&obfuscatedName);
        parcBuffer_Release(&originalNameBuffer);
        parcBuffer_Release(&reverseName);
        parcBuffer_Release(&plaintext);

        TSecStatsEntry *entry = tsecStatsEntry_Create(N);
        entry->obfuscateTime = endObfuscationTime - startObfuscationTime;
        entry->deobfuscateTime = endDeobfuscationTime - startDeobfuscationTime;
        entry->encryptTime = endEncryptionTime - startEncryptionTime;
        entry->decryptTime = endDecryptionTime - startDecryptionTime;

        // Append the stats entry
        parcLinkedList_Append(stats, entry);
        //displayStatsEntry(entry);

        parcStopwatch_Release(&timer);
    }

    displayTotalStats(stats);

    parcHashMap_Release(&table);
    parcLinkedList_Release(&stats);

    return 0;
}

