#include <parc/algol/parc_SafeMemory.h>
#include <parc/algol/parc_BufferComposer.h>
#include <parc/algol/parc_LinkedList.h>
#include <parc/algol/parc_Iterator.h>
#include <parc/algol/parc_HashMap.h>

#include <parc/developer/parc_StopWatch.h>
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
    return parcBuffer_Allocate(32);
}

// XXX: encode names using the codec, create TLV from the buffer, use TLV to create final name

static PARCBuffer *
_obfuscateName(PARCBuffer *encodedName)
{
    /*
    CCNxName *newName = ccnxName_CreateFromCString("ccnx:/");
    PARCBufferComposer *composer = parcBufferComposer_Create();
    for (size_t i = 0; i < ccnxName_GetSegmentCount(name); i++) {
        CCNxNameSegment *segment = ccnxName_GetSegmentAtIndex(name, i);
        char *segmentString = ccnxNameSegment_ToString(segment);
        PARCBuffer *segmentBuffer = parcBuffer_WrapCString(segmentString);
        parcBufferComposer_PutBuffer(composer, segmentBuffer);
        parcBuffer_Release(&segmentBuffer);
        parcMemory_Deallocate((void **) &segmentString);    

        PARCBuffer *prefix = parcBuffer_Flip(parcBufferComposer_CreateBuffer(composer));

        // XXX: hash the prefix
        // XXX: create a name segment
        // XXX: append segment to the name
    }
    */

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
    }

    PARCBuffer *finalName = parcBufferComposer_ProduceBuffer(fullComposer);
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
    parcCryptoHash_Release(&hashDigest);

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
    parcBuffer_Release(&nameDigest);
    
    return keyBuffer;
}

static PARCBuffer *
_createRandomBuffer(int size)
{
    PARCBuffer *buffer = parcBuffer_Allocate(size);
    PARCSecureRandom *rng = parcSecureRandom_Create();
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
    fprintf(stderr, "   - n        = The maximum length prefix to use when inserting names into the FIB\n");
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
        if (parcBuffer_Remaining(bufferString) == 0) {
            break;
        }

        char *string = parcBuffer_ToString(bufferString);
        parcBufferComposer_Release(&composer);

        // Create the original name and store it for later
        CCNxName *name = ccnxName_CreateFromCString(string);
        char *nameString = ccnxName_ToString(name);
        printf("Read %d: %s\n", index, nameString);
        PARCBuffer *nameBuffer = parcBuffer_AllocateCString(nameString);
        parcMemory_Deallocate(&nameString);
        parcLinkedList_Append(nameList, nameBuffer);

        ccnxName_Release(&name);
        index++;
    } while (true);

    PARCHashMap *table = parcHashMap_Create();

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

        //uint64_t elapsedTime = endTime - startTime;
        //printf("Time %d: %zu ns\n", index, elapsedTime);

        parcStopwatch_Release(&timer);
    }

    return 0;
}

