
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

#include "cpa.h"
#include "cpa_cy_im.h"
#include "cpa_cy_sym.h"
#include "cpa_sample_utils.h"
#include "icp_sal_user.h"
#include "icp_sal_poll.h"
#include "rt_utils.h"

#define TIMEOUT_MS  5000    // 5 seconds
#define MAX_PATH    1024
// Function qatMemAllocNUMA can only allocate a contiguous memory with size up
// to 1MB, otherwise return error.
#define MAX_HW_BUFSZ    1*1024*1024 // 1 MB
#define AES_BLOCKSZ     32          // 32 Bytes (256 bits)
// The following definition refers to /etc/dh895xcc_dev0.conf: SSL:
#define MAX_INSTANCES   8
#define MAX_THREADS     MAX_INSTANCES

#define ARRAY_LEN(arr)  (sizeof(arr) / sizeof(*(arr)))

typedef struct {
    const char *name;
    CpaStatus (*cipherPerformOp)(CpaInstanceHandle cyInstHandle,
                                 CpaCySymSessionCtx sessionCtx,
                                 char *src, unsigned int srcLen,
                                 char *dst, unsigned int dstLen);
    void (*symCallback)(void *pCallbackTag, CpaStatus status,
                        const CpaCySymOp operationType, void *pOpData,
                        CpaBufferList *pDstBuffer, CpaBoolean verifyResult);
} StrategyPack;

typedef struct {
    int isEnc;
    int nrThread;
    char fileToEncrypt[MAX_PATH];
    char fileToWrite[MAX_PATH];
    StrategyPack *strategy;
} CmdlineArgs;

typedef struct {
    char *dst;
} CallbackArgs;

typedef struct {
    char *src, *dst;
    unsigned int totalBytes;
    int isEnc;
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
    pthread_t workerId;
    int polling;
} QatAes256EcbSession;

typedef struct RunTime_ {
    struct timeval timeS;
    struct timeval timeE;
    struct RunTime_ *next;
} RunTime;

static QatHardware gQatHardware = {
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .isInit = 0,
    .nrCyInstHandles = 0,
    .idx = 0};
// .strategy will be directly accessed by the following functions, so this
// variable should be global.
static CmdlineArgs gCmdlineArgs = {
    .isEnc = 1,
    .nrThread = 1,
    .strategy = NULL};

// 256 bits-long
static Cpa8U sampleCipherKey[] = {
//    0     1     2     3     4     5     6     7
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,};

static RunTime *gRunTimeHead = NULL;
static pthread_mutex_t gMutex = PTHREAD_MUTEX_INITIALIZER;

void runTimePush(RunTime *pNode)
{
    pthread_mutex_lock(&gMutex);
    pNode->next = gRunTimeHead;
    gRunTimeHead = pNode;
    pthread_mutex_unlock(&gMutex);
}

void showStats(RunTime *pHead, unsigned int totalBytes)
{
    unsigned long usBegin = 0;
    unsigned long usEnd   = 0;
    double usDiff         = 0;

    for (RunTime *pCurr = pHead; pCurr != NULL; pCurr = pCurr->next) {
        usBegin = pCurr->timeS.tv_sec * 1e6 + pCurr->timeS.tv_usec;
        usEnd   = pCurr->timeE.tv_sec * 1e6 + pCurr->timeE.tv_usec;
        usDiff  += (usEnd - usBegin);
    }

    if (usDiff == 0 || totalBytes == 0) {
        RT_PRINT("Too fast to calculate throughput. Try larger workload.\n")
        return;
    }

    double throughput = ((double)totalBytes * 8) / usDiff;

    RT_PRINT("Time taken:     %9.3lf ms\n", usDiff / 1000);
    RT_PRINT("Throughput:     %9.3lf Mbit/s\n", throughput);
}

inline double calInterval(RunTime *rt)
{
    unsigned long usBegin = 0;
    unsigned long usEnd   = 0;
    double usDiff         = 0;

    usBegin = rt->timeS.tv_sec * 1e6 + rt->timeS.tv_usec;
    usEnd   = rt->timeE.tv_sec * 1e6 + rt->timeE.tv_usec;
    usDiff  = (usEnd - usBegin);

    return usDiff / 1000;
}

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
    RT_PRINT_DBG("Callback called with status = %d.\n", status);
    COMPLETE((struct COMPLETION_STRUCT *)pCallbackTag);
}

void *pollingThreadStart(void *args)
{
    QatAes256EcbSession *sess = (QatAes256EcbSession *)args;

    sess->polling = 1;
    while (sess->polling) {
        icp_sal_CyPollInstance(sess->cyInstHandle, 0);
        OS_SLEEP(1);
    }

    return NULL;
}

static void startPolling(QatAes256EcbSession *sess)
{
    CpaInstanceInfo2 info2 = {0};
    CHECK(cpaCyInstanceGetInfo2(sess->cyInstHandle, &info2));
    if (info2.isPolled == CPA_TRUE)
        pthread_create(&(sess->workerId), NULL, pollingThreadStart, sess);
}

static void stopPolling(QatAes256EcbSession *sess)
{
    sess->polling = 0;
}

static CpaStatus cipherPerformOpUpper(CpaInstanceHandle cyInstHandle,
                                    CpaCySymSessionCtx sessionCtx,
                                    char *src, unsigned int srcLen,
                                    char *dst, unsigned int dstLen)
{
    memcpy(dst, src, srcLen);
    memcpy(dst, src, srcLen);
    memcpy(dst, src, srcLen);

    return CPA_STATUS_SUCCESS;
}

static CpaStatus cipherPerformOpOnce(CpaInstanceHandle cyInstHandle,
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

    const unsigned int kMaxHwBufferSize = MAX_HW_BUFSZ;         // 1 MB
    const unsigned int kMaxSwBufferSize = 512 * 1024 * 1024;    // 512 MB

    unsigned int q = srcLen / kMaxHwBufferSize;
    unsigned int r = srcLen % kMaxHwBufferSize;
    RT_PRINT_DBG("srcLen / kMaxHwBufferSize = %d, srcLen // kMaxHwBufferSize = %d\n", q, r);
    if (r != 0) q++;
    Cpa32U numBuffers = q;
    RT_PRINT_DBG("\t=> numBuffers = %d\n", numBuffers);

    RunTime *rt = (RunTime *)calloc(1, sizeof(RunTime));

    // \begin stage #0: prepare input data
    gettimeofday(&rt->timeS, NULL);

    // Allocate memory for bufferlist and array of flat buffers in a contiguous
    // area and carve it up to reduce number of memory allocations required.
    Cpa32U bufferListMemSize =
        sizeof(CpaBufferList) + (numBuffers * sizeof(CpaFlatBuffer));

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
    CHECK(OS_MALLOC(&pOpData, sizeof(CpaCySymOpData)));

    // Increment by sizeof(CpaBufferList) to get at the array of flatbuffers.
    pFlatBuffer = (CpaFlatBuffer *)(pBufferList + 1);
    pBufferList->pBuffers = pFlatBuffer;
    pBufferList->numBuffers = numBuffers;
    pBufferList->pPrivateMetaData = pBufferMeta;

    // Copy data in src buffer to DMAble buffer
    CpaFlatBuffer *pFlatBufferIter = pFlatBuffer;
    Cpa32U bufferSize = 0;
    for (unsigned int i = 0, off = 0; i < numBuffers; i++, off += kMaxHwBufferSize) {
        bufferSize = (i != numBuffers-1) ? kMaxHwBufferSize : srcLen - off;
        CHECK(PHYS_CONTIG_ALLOC(&(pFlatBufferIter->pData), bufferSize));
        pFlatBufferIter->dataLenInBytes = bufferSize;
        memcpy(pFlatBufferIter->pData, src + off, bufferSize);
        pFlatBufferIter++;
    }

    gettimeofday(&rt->timeE, NULL);
    RT_PRINT("Time taken in stage #0: %.3f\n", calInterval(rt));
    // \end stage #0: prepare input data

    // \begin stage #1: consume data
    gettimeofday(&rt->timeS, NULL);

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
    pOpData->messageLenToCipherInBytes = srcLen;

    struct COMPLETION_STRUCT complete;
    COMPLETION_INIT(&complete);
    CHECK(cpaCySymPerformOp(cyInstHandle,
                            (void *)&complete,  // data sent as is to the callback function
                            pOpData,            // operational data struct
                            pBufferList,        // source buffer list
                            pBufferList,        // same src & dst for an in-place operation
                            NULL));
    RT_PRINT_DBG("Wait for completion\n");
    if (!COMPLETION_WAIT(&complete, TIMEOUT_MS)) {
        RT_PRINT_ERR("Timeout or interruption in cpaCySymPerformOp\n");
        rc = CPA_STATUS_FAIL;
        goto do_exit;
    }

    gettimeofday(&rt->timeE, NULL);
    RT_PRINT("Time taken in stage #1: %.3f\n", calInterval(rt));
    // \end stage #1: cosume data

    // \begin stage #2: copy output back
    gettimeofday(&rt->timeS, NULL);

    pFlatBufferIter = pFlatBuffer;
    for (unsigned int i = 0, off = 0; i < numBuffers; i++, off += kMaxHwBufferSize) {
        RT_PRINT_DBG("@i = %d, @numBuffers = %d\n", i, numBuffers);
        bufferSize = (i != numBuffers-1) ? kMaxHwBufferSize : srcLen - off;
        memcpy(dst + off, pFlatBufferIter->pData, bufferSize);
        pFlatBufferIter++;
    }

    gettimeofday(&rt->timeE, NULL);
    RT_PRINT("Time taken in stage #2: %.3f\n", calInterval(rt));
    // \end stage #2: copy output back

do_exit:
    COMPLETION_DESTROY(&complete);
    // Free all flat buffers
    pFlatBufferIter = pFlatBuffer;
    for (unsigned int i = 0; i < numBuffers; i++) {
        PHYS_CONTIG_FREE(pFlatBufferIter->pData);
        pFlatBufferIter++;
    }
    PHYS_CONTIG_FREE(pBufferMeta);
    OS_FREE(pBufferList);
    OS_FREE(pOpData);

    return rc;
}

static CpaStatus cipherPerformOpSync(CpaInstanceHandle cyInstHandle,
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
    Cpa32U numBuffers = 1;  // Only use 1 buffer in this case

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

    // \begin consume data block by block whose size is MAX_HW_BUFSZ
    struct COMPLETION_STRUCT complete;
    int q = srcLen / bufferSize;
    int r = srcLen % bufferSize;
    RT_PRINT_DBG("srcLen / bufferSize = %d, srcLen / bufferSize = %d\n", q, r);
    if (r != 0) q++;

    unsigned int bytesToEnc, bytesProduced = 0;
    for (int round = 0, off = 0; round < q; round++, off += bufferSize) {
        bytesToEnc = (round != q-1) ? bufferSize : srcLen - off;
        memcpy(pSrcBuffer, src + off, bytesToEnc);
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
        pOpData->messageLenToCipherInBytes = bytesToEnc;

        COMPLETION_INIT(&complete);
        RT_PRINT_DBG("Round %d (%d): %d bytes in\n", round, q, bytesToEnc);
        CHECK(cpaCySymPerformOp(cyInstHandle,
                                (void *)&complete,  // data sent as is to the callback function
                                pOpData,            // operational data struct
                                pBufferList,        // source buffer list
                                pBufferList,        // same src & dst for an in-place operation
                                NULL));
        RT_PRINT_DBG("Wait for completion\n");
        if (!COMPLETION_WAIT(&complete, TIMEOUT_MS)) {
            RT_PRINT_ERR("Timeout or interruption in cpaCySymPerformOp\n");
            rc = CPA_STATUS_FAIL;
            break;
        }
        RT_PRINT_DBG("Round %d (%d): %d bytes out\n", round, q, bytesToEnc);
        memcpy(dst + off, pSrcBuffer, bytesToEnc);
        bytesProduced += bytesToEnc;
    }
    dstLen = bytesProduced;
    assert(dstLen == srcLen);

    COMPLETION_DESTROY(&complete);
    PHYS_CONTIG_FREE(pSrcBuffer);
    PHYS_CONTIG_FREE(pBufferMeta);
    OS_FREE(pBufferList);
    OS_FREE(pOpData);

    return rc;
}

static void symCallbackAsync(void *pCallbackTag,
                             CpaStatus status,
                             const CpaCySymOp operationType,
                             void *pOpData_,
                             CpaBufferList *pDstBuffer,
                             CpaBoolean verifyResult)
{
    RT_PRINT_DBG("Callback called with status = %d.\n", status);
    CallbackArgs *cbArgs = (CallbackArgs *)pCallbackTag;
    CpaCySymOpData *pOpData = (CpaCySymOpData *)pOpData_;

    // \begin stage 2: copy result back & do post clean
    for (unsigned int i = 0, off = 0; i < pDstBuffer->numBuffers;
            i++, off += ((pDstBuffer->pBuffers)+i)->dataLenInBytes) {
        if (off + ((pDstBuffer->pBuffers)+i)->dataLenInBytes >
                pOpData->messageLenToCipherInBytes) {
            memcpy((cbArgs->dst)+off, ((pDstBuffer->pBuffers)+i)->pData,
                    pOpData->messageLenToCipherInBytes - off);
            off += (pOpData->messageLenToCipherInBytes - off);
            break;
        }
        memcpy((cbArgs->dst)+off, ((pDstBuffer->pBuffers)+i)->pData,
                ((pDstBuffer->pBuffers)+i)->dataLenInBytes);
    }

    // Do post clean
    PHYS_CONTIG_FREE(pDstBuffer->pPrivateMetaData);
    for (int i = 0; i < pDstBuffer->numBuffers; i++)
        PHYS_CONTIG_FREE(((pDstBuffer->pBuffers)+i)->pData);
    OS_FREE(pDstBuffer);
    OS_FREE(pOpData);
    // \end starge 2: copy result back & do post clean
}

static CpaStatus cipherPerformOpAsync(CpaInstanceHandle cyInstHandle,
                                      CpaCySymSessionCtx sessionCtx,
                                      char *src, unsigned int srcLen,
                                      char *dst, unsigned int dstLen)
{
    CpaStatus rc = CPA_STATUS_SUCCESS;

    const unsigned int kMaxHwBufferSize = MAX_HW_BUFSZ;
    const unsigned int numBuffers = 1;

    unsigned int bufferSize = numBuffers * kMaxHwBufferSize;
    RT_PRINT_DBG("@bufferSize = %d\n", bufferSize);
    unsigned int q = srcLen / bufferSize;
    unsigned int r = srcLen % bufferSize;
    RT_PRINT_DBG("@srcLen / bufferSize = %d, @srcLen // bufferSize = %d\n", q, r)
    if (r != 0) q++;
    RT_PRINT_DBG("\t => round = %d\n", q);

    unsigned int off = 0;
    for (unsigned int i = 0; i < q; i++) {

        RT_PRINT_DBG("@q = %d, @i = %d\n", q, i);

        CallbackArgs *cbArgs = (CallbackArgs *)calloc(1, sizeof(CallbackArgs));
        cbArgs->dst = dst + off;

        // \begin stage 0: alloc buffer & copy data to input buffer
        Cpa8U *pBufferMeta = NULL;
        Cpa32U bufferMetaSize = 0;
        CpaBufferList *pBufferList = NULL;
        CpaFlatBuffer *pFlatBuffer = NULL;
        CpaCySymOpData *pOpData = NULL;
        Cpa32U bufferListMemSize =
            sizeof(CpaBufferList) + (numBuffers * sizeof(CpaFlatBuffer));

        RT_PRINT_DBG("CP#0\n");

        CHECK(cpaCyBufferListGetMetaSize(cyInstHandle, numBuffers, &bufferMetaSize));
        CHECK(PHYS_CONTIG_ALLOC(&pBufferMeta, bufferMetaSize));
        CHECK(OS_MALLOC(&pBufferList, bufferListMemSize));
        CHECK(OS_MALLOC(&pOpData, sizeof(CpaCySymOpData)));

        RT_PRINT_DBG("CP#1\n");

        // Increment by sizeof(CpaBufferList) to get at the array of flatbuffers.
        pFlatBuffer = (CpaFlatBuffer *)(pBufferList + 1);
        for (int j = 0; j < numBuffers; j++) {
            CHECK(PHYS_CONTIG_ALLOC(&((pFlatBuffer + j)->pData), kMaxHwBufferSize));
            (pFlatBuffer + j)->dataLenInBytes = kMaxHwBufferSize;
        }
        pBufferList->pBuffers = pFlatBuffer;
        pBufferList->numBuffers = numBuffers;
        pBufferList->pPrivateMetaData = pBufferMeta;

        RT_PRINT_DBG("CP#2\n");

        // Do copy
        unsigned int bytesToEnc = 0;
        for (int j = 0; j < numBuffers; j++, off += kMaxHwBufferSize) {
            RT_PRINT_DBG("@q = %d, @i = %d, @j = %d\n", q, i, j);
            // Break if meets the last fragement
            if (off + kMaxHwBufferSize > srcLen) {
                RT_PRINT_DBG("dataLen = %d, bytesToCopy = %d\n",
                        (pFlatBuffer + j)->dataLenInBytes, srcLen - off);
                memcpy((pFlatBuffer + j)->pData, src + off, srcLen - off);
                bytesToEnc += (srcLen - off);
                off += (srcLen - off);
                break;
            }
            RT_PRINT_DBG("dataLen = %d, bytesToCopy = %d\n",
                    (pFlatBuffer + j)->dataLenInBytes, kMaxHwBufferSize);
            memcpy((pFlatBuffer + j)->pData, src + off, kMaxHwBufferSize);
            bytesToEnc += kMaxHwBufferSize;
        }

        RT_PRINT_DBG("CP#3\n");

        // \end stage 0: alloc buffer & copy data to input buffer

        // \begin stage 1: call QAT API to do encrypt
        pOpData->sessionCtx = sessionCtx;
        pOpData->packetType = CPA_CY_SYM_PACKET_TYPE_FULL;
        pOpData->cryptoStartSrcOffsetInBytes = 0;
        pOpData->messageLenToCipherInBytes = bytesToEnc;
        CHECK(cpaCySymPerformOp(cyInstHandle,
                                (void *)cbArgs,     // data sent as is to the callback function
                                pOpData,            // operational data struct
                                pBufferList,        // source buffer list
                                pBufferList,        // same src & dst for an in-place operation
                                NULL));
        // \end stage 1: call QAT API to do encrypt
        //
        RT_PRINT_DBG("CP#4\n");
    }
    assert(off == srcLen);

    return rc;
}

// It's thread-safety.
CpaStatus qatAes256EcbSessionInit(QatAes256EcbSession *sess, int isEnc)
{
    CpaStatus rc = CPA_STATUS_SUCCESS;
    Cpa32U sessionCtxSize = 0;
    CpaCySymSessionSetupData sessionSetupData = {0};

    // \begin acquire a CY instance
    pthread_mutex_lock(&gQatHardware.mutex);
    if (gQatHardware.isInit == -1) {
        rc = CPA_STATUS_FAIL;
        goto unlock;
    } else if (!gQatHardware.isInit) {
        // Find out all available CY instances at first time
        if (CPA_STATUS_SUCCESS != cpaCyGetNumInstances(&gQatHardware.nrCyInstHandles) ||
                gQatHardware.nrCyInstHandles == 0) {
            RT_PRINT_ERR("No instances found for 'SSL'\n");
            rc = CPA_STATUS_FAIL;
            gQatHardware.isInit = -1;
            goto unlock;
        } {
            RT_PRINT("%d instances found\n", gQatHardware.nrCyInstHandles);
        }
        if (CPA_STATUS_SUCCESS != cpaCyGetInstances(gQatHardware.nrCyInstHandles,
                                        gQatHardware.cyInstHandles)) {
            RT_PRINT_ERR("Failed to initialize instances.\n");
            rc = CPA_STATUS_FAIL;
            gQatHardware.isInit = -1;
            goto unlock;
        } {
            gQatHardware.isInit = 1;
        }
    }
    // FIXME: ensure that gQatHardware.idx < gQatHardware.nrCyInstHandles
    sess->cyInstHandle = gQatHardware.cyInstHandles[gQatHardware.idx++];
unlock:
    RT_PRINT_DBG("Exit critical section\n");
    pthread_mutex_unlock(&gQatHardware.mutex);
    CHECK(rc);
    // \end acquire a CY instance

    // \begin setup a QAT_AES-256-ECB session
    CHECK(cpaCyStartInstance(sess->cyInstHandle));
    CHECK(cpaCySetAddressTranslation(sess->cyInstHandle, sampleVirtToPhys));

    startPolling(sess);

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
    sessionSetupData.cipherSetupData.cipherKeyLenInBytes = sizeof(sampleCipherKey);
    sessionSetupData.cipherSetupData.cipherDirection =
        isEnc ? CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT : CPA_CY_SYM_CIPHER_DIRECTION_DECRYPT;
    RT_PRINT_DBG("@sessionSetupData.cipherSetupData.cipherKeyLenInBytes = %ld\n", sizeof(sampleCipherKey));

    // Determine size of session context to allocate
    CHECK(cpaCySymSessionCtxGetSize(sess->cyInstHandle, &sessionSetupData,
                &sessionCtxSize));
    // Allocate session context
    CHECK(PHYS_CONTIG_ALLOC(&sess->ctx, sessionCtxSize));
    // Initialize the Cipher session
    CHECK(cpaCySymInitSession(sess->cyInstHandle,
                              (gCmdlineArgs.strategy)->symCallback, // callback function
                              &sessionSetupData,                    // session setup data
                              sess->ctx));                          // output of the function
    // \end setup a QAT_AES-256-ECB session

    return rc;
}

void qatAes256EcbSessionFree(QatAes256EcbSession *sess)
{
    cpaCySymRemoveSession(sess->cyInstHandle, sess->ctx);
    PHYS_CONTIG_FREE(sess->ctx);
    stopPolling(sess);
    cpaCyStopInstance(sess->cyInstHandle);
}

CpaStatus qatAes256EcbEnc(char *src, unsigned int srcLen, char *dst,
        unsigned int dstLen, int isEnc)
{
    CpaStatus rc = CPA_STATUS_SUCCESS;
    QatAes256EcbSession *sess = calloc(1, sizeof(QatAes256EcbSession));
    CpaCySymStats64 symStats = {0};

    // Acquire a QAT_CY instance & initialize a QAT_CY_SYM_AES_256_ECB session
    qatAes256EcbSessionInit(sess, isEnc);

    // Perform Cipher operation (sync / async / batch, etc.)
    rc = (gCmdlineArgs.strategy)->
        cipherPerformOp(sess->cyInstHandle, sess->ctx, src, srcLen, dst, dstLen);

    // Wait for inflight requests before free resources
    symSessionWaitForInflightReq(sess->ctx);

    // Print statistics in this session
    CHECK(cpaCySymQueryStats64(sess->cyInstHandle, &symStats));
    RT_PRINT("Number of symmetic operation completed: %llu\n",
            (unsigned long long)symStats.numSymOpCompleted);

    qatAes256EcbSessionFree(sess);

    return rc;
}

// Thread entrypoint.
void *workerThreadStart(void *threadArgs)
{
    WorkerArgs *args = (WorkerArgs *)threadArgs;

    unsigned int totalBlocks = args->totalBytes / AES_BLOCKSZ;
    // Just check if args->totalBytes is legal: aligned to AES_BLOCKSZ
    unsigned int remainingBytes = args->totalBytes % AES_BLOCKSZ;
    assert(remainingBytes == 0);
    unsigned int strideInBlock = totalBlocks / args->nrThread;
    unsigned int remainingBlocks = totalBlocks % args->nrThread;
    unsigned int offInBytes = strideInBlock * args->threadId * AES_BLOCKSZ;

    // Assign remaining blocks to last worker
    if (remainingBlocks > 0 && args->threadId == (args->nrThread-1))
        strideInBlock += remainingBlocks;

    char *src = args->src + offInBytes;
    unsigned int srcLen = strideInBlock * AES_BLOCKSZ;
    char *dst = args->dst + offInBytes;
    unsigned int dstLen = srcLen;

    CHECK(qatAes256EcbEnc(src, srcLen, dst, dstLen, args->isEnc));

    return NULL;
}

unsigned int fileSize(int fd)
{
    struct stat statbuf;
    OS_CHECK(fstat(fd, &statbuf));
    return (unsigned int)statbuf.st_size;
}

void doEncryptFile(CmdlineArgs *cmdlineArgs)
{
    int fd0 = open(cmdlineArgs->fileToEncrypt, O_RDONLY);
    OS_CHECK(fd0);
    int fd1 = open(cmdlineArgs->fileToWrite, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
    OS_CHECK(fd1);

    unsigned int totalInBytes = fileSize(fd0);
    assert(totalInBytes > 0);
    // Aligned to AES_BLOCKSZ
    unsigned int r = totalInBytes % AES_BLOCKSZ;
    unsigned int totalOutBytes = (r == 0) ?
        totalInBytes : (totalInBytes - r + AES_BLOCKSZ);
    assert(totalInBytes <= totalOutBytes);

    // Use mmap to convert file-style read/write to memory-style read/write
    char *src = (char *)mmap(NULL, totalInBytes, PROT_READ, MAP_PRIVATE, fd0, 0);
    assert(src != NULL);
    // Use anonymous mmaped memory here to avoid pre-allocating fileToWrite
    char *dst = (char *)mmap(NULL, totalOutBytes, PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    assert(dst != NULL);

    // Since mmap always align size of mmapped memory to PAGE_SIZE (4KB in common)
    // and AES_BLOCKSZ is a factor of PAGE_SIZE, so aligned totalInBytes
    // (i.e. totalOutBytes) is less than size of mmapped memory. And, access to
    // region execeding size of mmaped file will get zero that is exactly we want
    // in doing encryption with AES. So we can safely use src/dst as input/output
    // buffer and totalOutBytes as buffer's length. See blow figure:
    //
    // Address space of the mmaped fileToEncrypt that is aligned to PAGE_SIZE:
    // ------------------------------------------------------------------------
    //     ...    | AES_BLOCK | AES_BLOCK |    ...    | AES_BLOCK |  PADDING  |
    // ------------------------------------------------------------------------
    // ----------------totalInBytes (not aligned)------->|
    // ---------------totalOutBytes (aligned to AES_BLOCK)------->|

    // Prepare thread arguments
    pthread_t workers[MAX_THREADS];
    WorkerArgs args[MAX_THREADS];
    for (int i = 0; i < cmdlineArgs->nrThread; i++) {
        args[i].src = src;
        args[i].dst = dst;
        args[i].totalBytes = totalOutBytes;
        args[i].isEnc = cmdlineArgs->isEnc;
        args[i].nrThread = cmdlineArgs->nrThread;
        args[i].threadId = i;
    }

    RunTime *rt = (RunTime *)calloc(1, sizeof(RunTime));
    gettimeofday(&rt->timeS, NULL);

    // Fire up all threads. Note that nrThread-1 pthreads are created and the
    // main thread is used as a worker as well
    for (int i = 1; i < cmdlineArgs->nrThread; i++)
        pthread_create(&workers[i], NULL, workerThreadStart, &args[i]);

    workerThreadStart((void *)&args[0]);

    // Wait for worker threads to complete
    for (int i = 1; i < cmdlineArgs->nrThread; i++)
        pthread_join(workers[i], NULL);

    gettimeofday(&rt->timeE, NULL);
    runTimePush(rt);

    // Show throughput
    showStats(gRunTimeHead, totalInBytes);

    // Print the first AES_BLOCK
    RT_PRINT_DBG("1st AES_BLOCK @src_buffer: %.*s\n", AES_BLOCKSZ, src);
    RT_PRINT_DBG("1st AES_BLOCK @dst_buffer: %.*s\n", AES_BLOCKSZ, dst);

    // Flush data in dst_buffer into fileToWrite
    ssize_t bytesWritten = write(fd1, dst, totalOutBytes);
    assert(bytesWritten == totalOutBytes);

    OS_CHECK(munmap(src, totalInBytes));
    OS_CHECK(munmap(dst, totalOutBytes));
    OS_CHECK(close(fd0));
    OS_CHECK(close(fd1));
}

void printUsage(const char *progname)
{
    printf("Usage: %s [options] <file_to_enc>\n", progname);
    printf("Program options:\n");
    printf("    -t  --thread <INT>          Number of thread to co-operate the given file\n");
    printf("    -w  --file_to_write <PATH>  File to save output data\n");
    printf("    -s  --strategy <STRING>     Which optimization strategy to use\n");
    printf("    -d  --decrypt               Switch to decryption mode\n");
    printf("    -h  --help                  This message\n");
}

// About code style: since QAT APIs use camel case, we begin to follow it.
int main(int argc, char *argv[])
{

    static StrategyPack strategies[] = {
        {"sync", cipherPerformOpSync, symCallback},
        {"once", cipherPerformOpOnce, symCallback},
        {"upper", cipherPerformOpUpper, symCallback},
        {"async", cipherPerformOpAsync, symCallbackAsync}};

    // Use "sync" by default
    gCmdlineArgs.strategy = &strategies[0];

    // \begin parse commandline args
    int opt;

    static struct option longOptions[] = {
        {"thread",        required_argument, 0, 't'},
        {"file_to_write", required_argument, 0, 'w'},
        {"strategy",      required_argument, 0, 's'},
        {"decrypt",       no_argument,       0, 'd'},
        {"help",          no_argument,       0, 'h'},
        {0,               0,                 0,  0 }};

    while ((opt = getopt_long(argc, argv, "t:w:s:dh", longOptions, NULL)) != -1) {
        switch (opt) {
            case 't':
                gCmdlineArgs.nrThread = atoi(optarg);
                assert(gCmdlineArgs.nrThread > 0 && gCmdlineArgs.nrThread <= MAX_THREADS);
                break;
            case 'w':
                sprintf(gCmdlineArgs.fileToWrite, "%s", optarg);
                break;
            case 'd':
                gCmdlineArgs.isEnc = 0;
                break;
            case 's':
                for (int i = 0; i < ARRAY_LEN(strategies); i++) {
                    if (strcmp(optarg, strategies[i].name) == 0) {
                        gCmdlineArgs.strategy = &strategies[i];
                        break;
                    }
                }
                // Check if given strategy name is legal or go die
                assert(strcmp((gCmdlineArgs.strategy)->name, optarg) == 0);
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
    // Construct fileToWrite
    if (strlen(gCmdlineArgs.fileToWrite) == 0) {
        char *suffix = gCmdlineArgs.isEnc ? "enc" : "dec";
        sprintf(gCmdlineArgs.fileToWrite, "%s.%s", gCmdlineArgs.fileToEncrypt, suffix);
    }
    // \end parse commandline args

    // CHECK(expr) := assert(CPA_STATUS_SUCCESS == (expr)). If assertion fails,
    // it will print error code/string, then exit. Your will find macro
    // CHECK(expr) useful when locating bug. So wrap some critical funtion
    // as far as possible. However, you can write your own error handler.
    CHECK(qaeMemInit());
    CHECK(icp_sal_userStartMultiProcess("SSL", CPA_FALSE));

    // Enter main function
    doEncryptFile(&gCmdlineArgs);

    icp_sal_userStop();
    qaeMemDestroy();

    return 0;
}
