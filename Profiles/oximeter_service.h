
#ifndef _OXIMETER_SERVICE_H_
#define _OXIMETER_SERVICE_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <bcomdef.h>

#define OXIMETER_SERVICE_SERV_UUID 0x1140
#define OXIMETER_SERVICE_SERV_UUID_BASE128(uuid) 0x00, 0x00, 0x00, 0x00, 0x00, \
    0x00, 0x00, 0xB0, 0x00, 0x40, 0x51, 0x04, LO_UINT16(uuid), HI_UINT16(uuid), \
    0x00, 0xF0

// OXIMETER Characteristic defines
#define OS_CHAR_ID                 0
#define OS_CHAR_UUID               0x1141
#define OS_CHAR_UUID_BASE128(uuid) 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
    0xB0, 0x00, 0x40, 0x51, 0x04, LO_UINT16(uuid), HI_UINT16(uuid), 0x00, 0xF0
#define OS_CHAR_LEN                500
#define OS_CHAR_LEN_MIN            1

// Callback when a characteristic value has changed
typedef void (*OximeterServiceChange_t)(uint16_t connHandle, uint8_t paramID,
                                      uint16_t len, uint8_t *pValue);

typedef struct
{
    OximeterServiceChange_t pfnChangeCb;          // Called when characteristic value changes
    OximeterServiceChange_t pfnCfgChangeCb;       // Called when characteristic CCCD changes
} OximeterServiceCBs_t;

extern bStatus_t OximeterService_AddService(uint8_t rspTaskId);

extern bStatus_t OximeterService_RegisterAppCBs(OximeterServiceCBs_t *appCallbacks);

extern bStatus_t OximeterService_SetParameter(uint8_t param,
                                            uint16_t len,
                                            void *value);

extern bStatus_t OximeterService_GetParameter(uint8_t param,
                                            uint16_t *len,
                                            void *value);


#ifdef __cplusplus
}
#endif

#endif /* _OXIMETER_SERVICE_H_ */
