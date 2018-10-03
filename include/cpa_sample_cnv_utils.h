/***************************************************************************
 *
 *   BSD LICENSE
 * 
 *   Copyright(c) 2007-2018 Intel Corporation. All rights reserved.
 *   All rights reserved.
 * 
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 * 
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 * 
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 *  version: QAT1.7.L.4.2.0-00012
 *
 ***************************************************************************/

/**
 *****************************************************************************
 * @file qat_compression_cnv_utils.h
 *
 * @defgroup compression
 *
 * @ingroup compression
 *
 * @description
 * Functions types and macros to determine CnV-E environment
 * Helper functions and macros to set the CnV flag in API
 *
 *
 ***************************************************************************/
#ifndef QAT_COMPRESSION_CNV_UTILS_H_
#define QAT_COMPRESSION_CNV_UTILS_H_

/* CNV with Recovery mode capability is present in DC API version 2.2
 * and higher.
 */
#if (CPA_DC_API_VERSION_NUM_MAJOR > 1) && (CPA_DC_API_VERSION_NUM_MINOR > 1)
#define CNV_RECOVERY(x) (x)->compressAndVerifyAndRecover
#define SET_CNV_RECOVERY(x, v) (CNV_RECOVERY(x) = v)
#else
#define CNV_RECOVERY(x) CPA_FALSE
#define SET_CNV_RECOVERY(x, v)
#endif

#define INIT_OPDATA(x, flag)                                                   \
    do                                                                         \
    {                                                                          \
        (x)->flushFlag = (flag);                                               \
        (x)->compressAndVerify = getCnVFlag();                                 \
        SET_CNV_RECOVERY(x, getCnVnRFlag());                                   \
        (x)->inputSkipData.skipMode = CPA_DC_SKIP_DISABLED;                    \
        (x)->outputSkipData.skipMode = CPA_DC_SKIP_DISABLED;                   \
    } while (0)

#define INIT_DC_DP_CNV_OPDATA(x)                                               \
    do                                                                         \
    {                                                                          \
        (x)->compressAndVerify = getCnVFlag();                                 \
        SET_CNV_RECOVERY(x, getCnVnRFlag());                                   \
    } while (0)

static CpaBoolean getCnVFlag(void) __attribute__((unused));
static CpaBoolean getCnVnRFlag(void) __attribute__((unused));
static const char *getCnVModeStr(void) __attribute__((unused));

static void getCnvFlagInternal(CpaBoolean *cnv, CpaBoolean *cnvnr);
static void EvaluateCnVFlag(const CpaDcInstanceCapabilities *const cap,
                            CpaBoolean *cnv,
                            CpaBoolean *cnvnr);
static CpaStatus getDcCapabilities(CpaDcInstanceCapabilities *capabilities);

static CpaBoolean getCnVFlag(void)
{
    static CpaBoolean cnvOpFlag;
    static CpaBoolean initialised = CPA_FALSE;

    if (initialised == CPA_FALSE)
    {
        getCnvFlagInternal(&cnvOpFlag, NULL);
        initialised = CPA_TRUE;
    }

    return cnvOpFlag;
}

static CpaBoolean getCnVnRFlag(void)
{
    static CpaBoolean cnvnrOpFlag;
    static CpaBoolean initialised = CPA_FALSE;

    if (initialised == CPA_FALSE)
    {
        getCnvFlagInternal(NULL, &cnvnrOpFlag);
        initialised = CPA_TRUE;
    }

    return cnvnrOpFlag;
}

static const char *getCnVModeStr(void)
{
    static const char *cmpWithVer = "Compression with Verification";
    static const char *cmpOnly = "Compression Only";

    return (getCnVFlag() == CPA_TRUE ? cmpWithVer : cmpOnly);
}

static void getCnvFlagInternal(CpaBoolean *cnv, CpaBoolean *cnvnr)
{
    CpaDcInstanceCapabilities cap = {0};
    if (getDcCapabilities(&cap) != CPA_STATUS_SUCCESS)
    {
        return EvaluateCnVFlag(NULL, cnv, cnvnr);
    }

    return EvaluateCnVFlag(&cap, cnv, cnvnr);
}

static void EvaluateCnVFlag(const CpaDcInstanceCapabilities *const cap,
                            CpaBoolean *cnv,
                            CpaBoolean *cnvnr)
{
    CpaBoolean fw_cnv_capable = CPA_FALSE;
    CpaBoolean cnv_loose_mode = CPA_FALSE;
    CpaBoolean cnvOpFlag = CPA_FALSE;
    CpaBoolean cnvnrOpFlag = CPA_FALSE;

    /* When capabilities are known, fill in the queried values */
    if (cap != NULL)
    {
        fw_cnv_capable = cap->compressAndVerify;
/* CNV mode capabilities is present in DC API version 2.1 and above */
#if (CPA_DC_API_VERSION_NUM_MAJOR > 1) && (CPA_DC_API_VERSION_NUM_MINOR > 0)
        cnv_loose_mode =
            (cap->compressAndVerifyStrict != CPA_TRUE) ? CPA_TRUE : CPA_FALSE;
#endif
        cnvnrOpFlag = CNV_RECOVERY(cap);
    }
    /* Determine the value of CompressAndVerify flag used by DP and
     * Traditional API depending on the FW CNV capability and CNV mode
     * of operation. The API will accept the submission of payload only
     * if this flag value is correct for the combination.
     * FW-CNV-CAPABLE MODE PERMITTED-OPERATION CNVFLAG
     *    Y            S    CompressWithVerify  TRUE
     *    Y            L    Compress only       FALSE
     *    N            S    NONE                 NA
     *    N            L    Compress only       FALSE
     */
    if (fw_cnv_capable == CPA_TRUE)
    {
        cnvOpFlag = (cnv_loose_mode == CPA_FALSE) ? CPA_TRUE : CPA_FALSE;
    }
    else
    {
        cnvOpFlag = CPA_FALSE;
    }

    /* CNV Recovery only possble when
     * CNV is enabled/present.
     */
    if (cnvOpFlag == CPA_FALSE)
    {
        cnvnrOpFlag = CPA_FALSE;
    }

    if (cnv != NULL)
        *cnv = cnvOpFlag;

    if (cnvnr != NULL)
        *cnvnr = cnvnrOpFlag;

    return;
}

static CpaStatus getDcCapabilities(CpaDcInstanceCapabilities *capabilities)
{
    CpaStatus status;
    CpaInstanceHandle instHandle;
    Cpa16U numInstances = 0;

    /* Get the number of instances */
    status = cpaDcGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != status)
        return CPA_STATUS_FAIL;

    if (numInstances == 0)
        return CPA_STATUS_FAIL;

    status = cpaDcGetInstances(1, &instHandle);
    if (status != CPA_STATUS_SUCCESS)
        return CPA_STATUS_FAIL;

    status = cpaDcQueryCapabilities(instHandle, capabilities);
    if (CPA_STATUS_SUCCESS != status)
        return CPA_STATUS_FAIL;

    return CPA_STATUS_SUCCESS;
}
#endif /* QAT_COMPRESSION_CNV_UTILS_H_ */
