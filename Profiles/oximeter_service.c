#include <string.h>
#include <ti/common/cc26xx/uartlog/UartLog.h>  // Comment out if using xdc Log
#include <icall.h>
#include "icall_ble_api.h"
#include "oximeter_service.h"

// Oximeter_Service Service UUID
CONST uint8_t OximeterServiceUUID[ATT_UUID_SIZE] =
{
    OXIMETER_SERVICE_SERV_UUID_BASE128(OXIMETER_SERVICE_SERV_UUID)
};

// Oximeter Characteristic UUID
CONST uint8_t os_CHAR_UUID[ATT_UUID_SIZE] =
{
    OS_CHAR_UUID_BASE128(OS_CHAR_UUID)
};

static OximeterServiceCBs_t *pAppCBs = NULL;
static uint8_t bs_icall_rsp_task_id = INVALID_TASK_ID;

// Service declaration
static CONST gattAttrType_t OximeterServiceDecl =
{ ATT_UUID_SIZE, OximeterServiceUUID };

// Characteristic Properties (for declaration)
static uint8_t os_CHAR_Props = GATT_PROP_NOTIFY | GATT_PROP_READ;

// Characteristic Value variable
static uint8_t os_CHAR_Val[OS_CHAR_LEN] = {0};

// Length of data in characteristic "BUTTON0" Value variable, initialized to minimal size.
static uint16_t os_CHAR_ValLen = OS_CHAR_LEN_MIN;

// Characteristic Client Characteristic Configuration Descriptor
static gattCharCfg_t *os_CHAR_Config;

static gattAttribute_t Oximeter_ServiceAttrTbl[] =
{
    // Oximeter_Service Service Declaration
    {
        { ATT_BT_UUID_SIZE, primaryServiceUUID },
        GATT_PERMIT_READ,
        0,
        (uint8_t *)&OximeterServiceDecl
    },
    // BUTTON0 Characteristic Declaration
    {
        { ATT_BT_UUID_SIZE, characterUUID },
        GATT_PERMIT_READ,
        0,
        &os_CHAR_Props
    },
    // BUTTON0 Characteristic Value
    {
        { ATT_UUID_SIZE, os_CHAR_UUID },
        GATT_PERMIT_READ,
        0,
        os_CHAR_Val
    },
    // BUTTON0 CCCD
    {
        { ATT_BT_UUID_SIZE, clientCharCfgUUID },
        GATT_PERMIT_READ | GATT_PERMIT_WRITE,
        0,
        (uint8_t *)&os_CHAR_Config
    },
};

static bStatus_t Oximeter_Service_ReadAttrCB(uint16_t connHandle,
                                           gattAttribute_t *pAttr,
                                           uint8_t *pValue,
                                           uint16_t *pLen,
                                           uint16_t offset,
                                           uint16_t maxLen,
                                           uint8_t method);
static bStatus_t Oximeter_Service_WriteAttrCB(uint16_t connHandle,
                                            gattAttribute_t *pAttr,
                                            uint8_t *pValue,
                                            uint16_t len,
                                            uint16_t offset,
                                            uint8_t method);

CONST gattServiceCBs_t Oximeter_ServiceCBs =
{
    Oximeter_Service_ReadAttrCB, // Read callback function pointer
    Oximeter_Service_WriteAttrCB, // Write callback function pointer
    NULL                     // Authorization callback function pointer
};

extern bStatus_t OximeterService_AddService(uint8_t rspTaskId)
{
    uint8_t status;

    os_CHAR_Config = (gattCharCfg_t *)ICall_malloc(
        sizeof(gattCharCfg_t) * linkDBNumConns);
    if(os_CHAR_Config == NULL)
    {
        return(bleMemAllocError);
    }

    GATTServApp_InitCharCfg(LINKDB_CONNHANDLE_INVALID, os_CHAR_Config);

    status = GATTServApp_RegisterService(Oximeter_ServiceAttrTbl,
                                         GATT_NUM_ATTRS(Oximeter_ServiceAttrTbl),
                                         GATT_MAX_ENCRYPT_KEY_SIZE,
                                         &Oximeter_ServiceCBs);
    Log_info1("Registered service, %d attributes",
              GATT_NUM_ATTRS(Oximeter_ServiceAttrTbl));
    bs_icall_rsp_task_id = rspTaskId;

    return(status);
}

bStatus_t OximeterService_RegisterAppCBs(OximeterServiceCBs_t *appCallbacks)
{
    if(appCallbacks)
    {
        pAppCBs = appCallbacks;
        Log_info1("Registered callbacks to application. Struct %p",
                  (uintptr_t)appCallbacks);
        return(SUCCESS);
    }
    else
    {
        Log_warning0("Null pointer given for app callbacks.");
        return(FAILURE);
    }
}

bStatus_t OximeterService_SetParameter(uint8_t param, uint16_t len, void *value)
{
    if (param != OS_CHAR_ID) {
        Log_error1("SetParameter: Parameter #%d not valid.", param);
        return(INVALIDPARAMETER);
    }

    bStatus_t ret = SUCCESS;
    uint8_t  *pAttrVal;
    uint16_t *pValLen;
    uint16_t valMinLen;
    uint16_t valMaxLen;
    uint8_t sendNotiInd = FALSE;
    gattCharCfg_t *attrConfig;
    uint8_t needAuth;

    pAttrVal = os_CHAR_Val;
    pValLen = &os_CHAR_ValLen;
    valMinLen = OS_CHAR_LEN_MIN;
    valMaxLen = OS_CHAR_LEN;
    sendNotiInd = TRUE;
    attrConfig = os_CHAR_Config;
    needAuth = FALSE;  // Change if authenticated link is required for sending.
    Log_info2("SetParameter : %s len: %d", (uintptr_t)"OS CHAR", len);

    // Check bounds, update value and send notification or indication if possible.
    if(len <= valMaxLen && len >= valMinLen)
    {
        memcpy(pAttrVal, value, len);
        *pValLen = len; // Update length for read and get.

        if(sendNotiInd)
        {
            Log_info2("Trying to send noti/ind: connHandle %x, %s",
                      attrConfig[0].connHandle,
                      (uintptr_t)((attrConfig[0].value ==
                                   0) ? "\x1b[33mNoti/ind disabled\x1b[0m" :
                                  (attrConfig[0].value ==
                                   1) ? "Notification enabled" :
                                  "Indication enabled"));
            // Try to send notification.
            GATTServApp_ProcessCharCfg(attrConfig, pAttrVal, needAuth,
                                       Oximeter_ServiceAttrTbl,
                                       GATT_NUM_ATTRS(
                                               Oximeter_ServiceAttrTbl),
                                       bs_icall_rsp_task_id,
                                       Oximeter_Service_ReadAttrCB);
        }
    }
    else
    {
        Log_error3("Length outside bounds: Len: %d MinLen: %d MaxLen: %d.", len,
                   valMinLen,
                   valMaxLen);
        ret = bleInvalidRange;
    }

    return(ret);
}

bStatus_t OximeterService_GetParameter(uint8_t param, uint16_t *len, void *value)
{
    bStatus_t ret = SUCCESS;
    switch(param)
    {
    default:
        Log_error1("GetParameter: Parameter #%d not valid.", param);
        ret = INVALIDPARAMETER;
        break;
    }
    return(ret);
}

static uint8_t OximeterService_findCharParamId(gattAttribute_t *pAttr)
{
    // Is this a Client Characteristic Configuration Descriptor?
    if(ATT_BT_UUID_SIZE == pAttr->type.len && GATT_CLIENT_CHAR_CFG_UUID ==
       *(uint16_t *)pAttr->type.uuid)
    {
        return(OximeterService_findCharParamId(pAttr - 1)); // Assume the value attribute precedes CCCD and recurse
    }
    else if(ATT_UUID_SIZE == pAttr->type.len &&
            !memcmp(pAttr->type.uuid, os_CHAR_UUID, pAttr->type.len))
    {
        return(OS_CHAR_ID);
    }
    else
    {
        return(0xFF); // Not found. Return invalid.
    }
}

static bStatus_t Oximeter_Service_ReadAttrCB(uint16_t connHandle,
                                           gattAttribute_t *pAttr,
                                           uint8_t *pValue, uint16_t *pLen,
                                           uint16_t offset,
                                           uint16_t maxLen,
                                           uint8_t method)
{
    bStatus_t status = SUCCESS;
    uint16_t valueLen;
    uint8_t paramID = 0xFF;

    // Find settings for the characteristic to be read.
    paramID = OximeterService_findCharParamId(pAttr);
    if (paramID != OS_CHAR_ID) {
        Log_error0("Attribute was not found.");
        return(ATT_ERR_ATTR_NOT_FOUND);
    }

    valueLen = os_CHAR_ValLen;

    Log_info4("ReadAttrCB : %s connHandle: %d offset: %d method: 0x%02x",
              (uintptr_t)"CHARACTERISTIC",
              connHandle,
              offset,
              method);

    // Check bounds and return the value
    if(offset > valueLen)   // Prevent malicious ATT ReadBlob offsets.
    {
        Log_error0("An invalid offset was requested.");
        status = ATT_ERR_INVALID_OFFSET;
    }
    else
    {
        *pLen = MIN(maxLen, valueLen - offset); // Transmit as much as possible
        memcpy(pValue, pAttr->pValue + offset, *pLen);
    }

    return(status);
}

static bStatus_t Oximeter_Service_WriteAttrCB(uint16_t connHandle,
                                            gattAttribute_t *pAttr,
                                            uint8_t *pValue, uint16_t len,
                                            uint16_t offset,
                                            uint8_t method)
{
    bStatus_t status = SUCCESS;
    uint8_t paramID = 0xFF;

    // See if request is regarding a Client Characterisic Configuration
    if(ATT_BT_UUID_SIZE == pAttr->type.len && GATT_CLIENT_CHAR_CFG_UUID ==
       *(uint16_t *)pAttr->type.uuid)
    {
        Log_info3("WriteAttrCB (CCCD): param: %d connHandle: %d %s",
                  OximeterService_findCharParamId(pAttr),
                  connHandle,
                  (uintptr_t)(method ==
                              GATT_LOCAL_WRITE ? "- restoring bonded state" :
                              "- OTA write"));

        // Allow notification and indication, but do not check if really allowed per CCCD.
        status = GATTServApp_ProcessCCCWriteReq(
            connHandle, pAttr, pValue, len,
            offset,
            GATT_CLIENT_CFG_NOTIFY |
            GATT_CLIENT_CFG_INDICATE);
        if(SUCCESS == status && pAppCBs && pAppCBs->pfnCfgChangeCb)
        {
            pAppCBs->pfnCfgChangeCb(connHandle,
                                    OximeterService_findCharParamId(
                                        pAttr), len, pValue);
        }

        return(status);
    }

    // Find settings for the characteristic to be written.
    paramID = OximeterService_findCharParamId(pAttr);
    switch(paramID)
    {
    default:
        Log_error0("Attribute was not found.");
        return(ATT_ERR_ATTR_NOT_FOUND);
    }
}

