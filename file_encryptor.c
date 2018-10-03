
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>

#include "cpa.h"
#include "cpa_cy_im.h"
#include "cpa_cy_sym.h"
#include "cpa_sample_utils.h"
#include "icp_sal_user.h"
#include "rt_utils.h"

#define TIMEOUT_MS  5000 /* 5 seconds */
#define MAX_PATH     1024
// Function qatMemAllocNUMA can only allocate a contiguous memory with size up
// to 4MB, otherwise return error.
#define MAX_HW_BUFSZ    4*1024*1024 // 4MB
#define AES_BLOCKSZ     32          // Bytes
#define MAX_INSTANCES   16

typedef struct {
    int isDebug;
    int isAsync;
    int nrBatch;
    int nrThread;
    char fileToEncrypt[MAX_PATH];
    char fileToWrite[MAX_PATH];
} CmdlineArgs;

typedef struct {
    char *src;
    char *dst;
    unsigned int totalBytes;    // Should round to times of AES_BLOCKSZ
    int nrBatch;
    int isAsync;
    int threadId;
    int nrThread;
} WorkerArgs;

typedef struct {
    pthread_mutex_t mutex;
    int isInit;
    int idx;
    Cpa16U nrCyInstHandles;
    CpaInstanceHandle cyInstHandles[MAX_INSTANCES];
} QatHardware;

typedef struct {
    CpaInstanceHandle cyInstHandle;
    CpaCySymSessionCtx ctx;
} QatAes256EcbSession;

static QatHardware gQatHardware = {
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .isInit = 0,
    .nrCyInstHandles = 0,
    .idx = 0};
static CmdlineArgs gCmdlineArgs = {
    .isDebug = 1,
    .isAsync = 0,
    .nrBatch = 1,
    .nrThread = 1,
    .fileToWrite = "/dev/stdout"};

// 256 bits-long key
static Cpa8U sampleCipherKey[] = {"12345678901234567890123456789012"};

// Callback function
//
// This function is "called back" (invoked by the implementation of
// the API) when the asynchronous operation has completed.  The
// context in which it is invoked depends on the implementation, but
// as described in the API it should not sleep (since it may be called
// in a context which does not permit sleeping, e.g. a Linux bottom
// half).
//
// This function can perform whatever processing is appropriate to the
// application.  For example, it may free memory, continue processing
// of a decrypted packet, etc.  In this example, the function only
// sets the complete variable to indicate it has been called.
static void symCallback(void *pCallbackTag,
                        CpaStatus status,
                        const CpaCySymOp operationType,
                        void *pOpData,
                        CpaBufferList *pDstBuffer,
                        CpaBoolean verifyResult)
{
    if (NULL != pCallbackTag)
    {
        /* indicate that the function has been called */
        COMPLETE((struct COMPLETION_STRUCT *)pCallbackTag);
    }
}

/*
 * This function performs a cipher operation.
 */
static CpaStatus cipherPerformOp(CpaInstanceHandle cyInstHandle,
                                 CpaCySymSessionCtx sessionCtx,
                                 char *src, unsigned int srcLen,
                                 char *dst, unsigned int dstLen)
{
    CpaStatus rc = CPA_STATUS_SUCCESS;

    Cpa8U *pBufferMeta = NULL;
    Cpa32U bufferMetaSize = 0;
    CpaBufferList *pBufferList = NULL;
    CpaFlatBuffer *pFlatBuffer = NULL;
    CpaCySymOpData *pOpData = NULL;
    Cpa32U bufferSize = MAX_HW_BUFSZ;
    Cpa32U numBuffers = 1;  // Only user 1 buffer in this case

    // Check srcLen is times of AES_BLOCKSZ Bytes (256 bits)
    int q = srcLen / AES_BLOCKSZ;
    int r = srcLen % AES_BLOCKSZ;
    if (r != 0) {
        PRINT_ERR("Length of src is invalid\n");
        return CPA_STATUS_FAIL;
    }

    // Allocate memory for bufferlist and array of flat buffers in a contiguous
    // area and carve it up to reduce number of memory allocations required.
    Cpa32U bufferListMemSize =
        sizeof(CpaBufferList) + (numBuffers * sizeof(CpaFlatBuffer));
    Cpa8U *pSrcBuffer = NULL;

    // Different implementations of the API require different
    // amounts of space to store meta-data associated with buffer
    // lists.  We query the API to find out how much space the current
    // implementation needs, and then allocate space for the buffer
    // meta data, the buffer list, and for the buffer itself.  We also
    // allocate memory for the initialization vector.  We then
    // populate this memory with the required data.
    CHECK(cpaCyBufferListGetMetaSize(cyInstHandle, numBuffers, &bufferMetaSize));
    CHECK(PHYS_CONTIG_ALLOC(&pBufferMeta, bufferMetaSize));
    CHECK(OS_MALLOC(&pBufferList, bufferListMemSize));
    CHECK(PHYS_CONTIG_ALLOC(&pSrcBuffer, bufferSize));
    CHECK(OS_MALLOC(&pOpData, sizeof(CpaCySymOpData)));

    // Increment by sizeof(CpaBufferList) to get at the array of flatbuffers.
    pFlatBuffer = (CpaFlatBuffer *)(pBufferList + 1);
    pBufferList->pBuffers = pFlatBuffer;
    pBufferList->numBuffers = 1;
    pBufferList->pPrivateMetaData = pBufferMeta;

    // \begin consume data block by block where block size is MAX_HW_BUFSZ (4MB)
    int round, off;
    for (round = 0, off = 0; round < q; round++, off += bufferSize) {
        memcpy(pSrcBuffer, src + off, bufferSize);
        pFlatBuffer->pData = pSrcBuffer;
        pFlatBuffer->dataLenInBytes = bufferSize;

        // Populate the structure containing the operational data needed
        // to run the algorithm:
        // - packet type information (the algorithm can operate on a full
        //   packet, perform a partial operation and maintain the state or
        //   complete the last part of a multi-part operation)
        // - the initialization vector and its length
        // - the offset in the source buffer
        // - the length of the source message
        pOpData->sessionCtx = sessionCtx;
        pOpData->packetType = CPA_CY_SYM_PACKET_TYPE_FULL;
        pOpData->cryptoStartSrcOffsetInBytes = 0;
        pOpData->messageLenToCipherInBytes = bufferSize;

        CHECK(cpaCySymPerformOp(cyInstHandle,
                                NULL,              /* data sent as is to the callback function*/
                                pOpData,           /* operational data struct */
                                pBufferList,       /* source buffer list */
                                pBufferList,       /* same src & dst for an in-place operation*/
                                NULL));
        memcpy(dst + off, pSrcBuffer, bufferSize);
    }
    // Update dstLen
    dstLen = srcLen;

    PHYS_CONTIG_FREE(pSrcBuffer);
    OS_FREE(pBufferList);
    PHYS_CONTIG_FREE(pBufferMeta);
    OS_FREE(pOpData);

    return rc;
}

// It's thread-safety
CpaStatus qatAes256EcbSessionInit(QatAes256EcbSession *sess)
{
    CpaStatus rc = CPA_STATUS_SUCCESS;
    Cpa32U sessionCtxSize = 0;
    CpaCySymSessionSetupData sessionSetupData = {0};

    // \begin acquire a CY instance
    pthread_mutex_lock(&gQatHardware.mutex);
    // Find out all available CY instances at first time
    if (!gQatHardware.isInit) {
        rc = cpaCyGetNumInstances(&gQatHardware.nrCyInstHandles);
        if (rc != CPA_STATUS_SUCCESS) {
            PRINT_ERR("Failed to initialize number of instances.\nn");
            goto unlock;
        }
        if (gQatHardware.nrCyInstHandles == 0) {
            PRINT_ERR("No instances found for 'SSL'\n");
            PRINT_ERR("Please check your section names in the config file.\n");
            PRINT_ERR("Also make sure to use config file version 2.\n");
            goto unlock;
        }
        rc = cpaCyGetInstances(MAX_INSTANCES, gQatHardware.cyInstHandles);
        if (rc != CPA_STATUS_SUCCESS) {
            PRINT_ERR("Failed to initialize instances.\n");
            goto unlock;
        }
    }
    // FIXME: ensure that gQatHardware.idx < gQatHardware.nrCyInstHandles
    sess->cyInstHandle = gQatHardware.cyInstHandles[gQatHardware.idx++];
unlock:
    pthread_mutex_unlock(&gQatHardware.mutex);
    CHECK(rc);
    // \end acquire a CY instance

    // \begin setup a QAT_AES-256-ECB session
    CHECK(cpaCyStartInstance(sess->cyInstHandle));
    CHECK(cpaCySetAddressTranslation(sess->cyInstHandle, sampleVirtToPhys));

    // We now populate the fields of the session operational data and create
    // the session.  Note that the size required to store a session is
    // implementation-dependent, so we query the API first to determine how
    // much memory to allocate, and then allocate that memory.
    //
    // Populate the session setup structure for the operation required
    sessionSetupData.sessionPriority = CPA_CY_PRIORITY_NORMAL;
    sessionSetupData.symOperation = CPA_CY_SYM_OP_CIPHER;
    sessionSetupData.cipherSetupData.cipherAlgorithm =
        CPA_CY_SYM_CIPHER_AES_ECB;
    sessionSetupData.cipherSetupData.pCipherKey = sampleCipherKey;
    sessionSetupData.cipherSetupData.cipherKeyLenInBytes =
        sizeof(sampleCipherKey);
    sessionSetupData.cipherSetupData.cipherDirection =
        CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT;

    // Determine size of session context to allocate
    CHECK(cpaCySymSessionCtxGetSize(sess->cyInstHandle, &sessionSetupData,
                &sessionCtxSize));
    // Allocate session context
    CHECK(PHYS_CONTIG_ALLOC(&sess->ctx, sessionCtxSize));
    // Initialize the Cipher session
    CHECK(cpaCySymInitSession(sess->cyInstHandle,
                              symCallback,       // callback function
                              &sessionSetupData, // session setup data
                              sess->ctx));       // output of the function
    // \end setup a QAT_AES-256-ECB session

    return rc;
}

void qatAes256EcbSessionFree(QatAes256EcbSession *sess)
{
    cpaCySymRemoveSession(sess->cyInstHandle, sess->ctx);
    PHYS_CONTIG_FREE(sess->ctx);
    cpaCyStopInstance(sess->cyInstHandle);
}

CpaStatus qatAes256EcbEnc(char *src, unsigned int srcLen, char *dst,
        unsigned int dstLen)
{
    CpaStatus rc = CPA_STATUS_SUCCESS;
    QatAes256EcbSession *sess = calloc(1, sizeof(QatAes256EcbSession));

    // Acquire a QAT_CY instance & initialize a QAT_CY_SYM_AES_256_ECB session
    qatAes256EcbSessionInit(sess);
    // Perform Cipher operation (sync / async / batch, etc.)
    rc = cipherPerformOp(sess->cyInstHandle, sess->ctx, src, srcLen, dst, dstLen);
    // Wait for inflight requests before removing session
    symSessionWaitForInflightReq(sess->ctx);
    qatAes256EcbSessionFree(sess);

    return rc;
}

unsigned int fileSize(FILE *fp)
{
    struct stat statbuf;
    int rc;
    int fd = fileno(fp);

    rc = fstat(fd, &statbuf);
    assert(rc == 0);

    return (unsigned int)statbuf.st_size;
}

// Thread entrypoint.
void *workerThreadStart(void *threadArgs)
{
    WorkerArgs *args = (WorkerArgs *)threadArgs;

    unsigned int totalBlocks = args->totalBytes / AES_BLOCKSZ;
    unsigned int strideInBlock = totalBlocks / args->nrThread;
    unsigned int remainingBlocks = totalBlocks % args->nrThread;
    unsigned int offInBytes = (strideInBlock * AES_BLOCKSZ) * args->threadId;

    // Assign remaining blocks to last worker
    if (remainingBlocks > 0 && args->threadId == (args->nrThread-1))
        strideInBlock += remainingBlocks;

    char *src = args->src + offInBytes;
    unsigned int srcLen = strideInBlock * AES_BLOCKSZ;
    char *dst = args->dst + offInBytes;
    unsigned int dstLen = srcLen;

    CHECK(qatAes256EcbEnc(src, srcLen, dst, dstLen));

    return NULL;
}

void doEncryptFile(char *fileToEncrypt, char *fileToWrite)
{
    // TODO
}

void printUsage(const char *progname)
{
    printf("Usage: %s [options] <file_to_enc>\n", progname);
    printf("Program options:\n");
    printf("    -t  --thread <INT>          TODO\n");
    printf("    -b  --batch-number <INT>    TODO\n");
    printf("    -s  --(a)sync               TODO\n");
    printf("    -o  --output-file <PATH>    File to save output data\n");
    printf("    -h  --help                  This message\n");
}

// About code style: since QAT APIs use camel case, we begin to follow it.
int main(int argc, char *argv[])
{
    // \begin parse commandline args
    int opt;

    static struct option longOptions[] = {
        {"async",        no_argument,       0, 'a'},
        {"thread",       required_argument, 0, 't'},
        {"batch-number", required_argument, 0, 'b'},
        {"output-file",  required_argument, 0, 'o'},
        {"help",         no_argument,       0, 'h'},
        {0,              0,                 0,  0 }
    };

    while ((opt = getopt_long(argc, argv, "t:b:o:ah", longOptions, NULL)) != -1) {
        switch (opt) {
            case 'a':
                gCmdlineArgs.isAsync = 1;
                break;
            case 't':
                gCmdlineArgs.nrThread = atoi(optarg);
                assert(gCmdlineArgs.nrThread > 0);
                break;
            case 'b':
                gCmdlineArgs.nrBatch = atoi(optarg);
                assert(gCmdlineArgs.nrBatch > 0);
                break;
            case 'o':
                sprintf(gCmdlineArgs.fileToWrite, "%s", optarg);
                break;
            case 'h':
            case '?':
            default:
                printUsage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (optind < argc) {
        sprintf(gCmdlineArgs.fileToEncrypt, "%s", argv[optind++]);
    } else {
        printUsage(argv[0]);
        exit(EXIT_FAILURE);
    }
    // \end parse commandline args

    // CHECK(expr) := assert(CPA_STATUS_SUCCESS == (expr)). If assertion fails,
    // it will print error code/string, then exit. Your will find macro
    // CHECK(expr) useful when locating bug. So wrap some critical funtion
    // as far as possible. However, you can write your own error handler.
    CHECK(qaeMemInit());
    CHECK(icp_sal_userStartMultiProcess("SSL", CPA_FALSE));

    // Enter main function
    doEncryptFile(gCmdlineArgs.fileToEncrypt, gCmdlineArgs.fileToWrite);

    icp_sal_userStop();
    qaeMemDestroy();

    return 0;
}
