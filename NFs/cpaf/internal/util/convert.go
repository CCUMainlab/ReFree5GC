package util

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/free5gc/cpaf/internal/logger"
	"github.com/free5gc/openapi/models"
)

var policyTriggerArray = []models.PolicyControlRequestTrigger{
	models.PolicyControlRequestTrigger_PLMN_CH,
	models.PolicyControlRequestTrigger_RES_MO_RE,
	models.PolicyControlRequestTrigger_AC_TY_CH,
	models.PolicyControlRequestTrigger_UE_IP_CH,
	models.PolicyControlRequestTrigger_UE_MAC_CH,
	models.PolicyControlRequestTrigger_AN_CH_COR,
	models.PolicyControlRequestTrigger_US_RE,
	models.PolicyControlRequestTrigger_APP_STA,
	models.PolicyControlRequestTrigger_APP_STO,
	models.PolicyControlRequestTrigger_AN_INFO,
	models.PolicyControlRequestTrigger_CM_SES_FAIL,
	models.PolicyControlRequestTrigger_PS_DA_OFF,
	models.PolicyControlRequestTrigger_DEF_QOS_CH,
	models.PolicyControlRequestTrigger_SE_AMBR_CH,
	models.PolicyControlRequestTrigger_QOS_NOTIF,
	models.PolicyControlRequestTrigger_NO_CREDIT,
	models.PolicyControlRequestTrigger_PRA_CH,
	models.PolicyControlRequestTrigger_SAREA_CH,
	models.PolicyControlRequestTrigger_SCNN_CH,
	models.PolicyControlRequestTrigger_RE_TIMEOUT,
	models.PolicyControlRequestTrigger_RES_RELEASE,
	models.PolicyControlRequestTrigger_SUCC_RES_ALLO,
	models.PolicyControlRequestTrigger_RAT_TY_CH,
	models.PolicyControlRequestTrigger_REF_QOS_IND_CH,
	models.PolicyControlRequestTrigger_NUM_OF_PACKET_FILTER,
	models.PolicyControlRequestTrigger_UE_STATUS_RESUME,
	models.PolicyControlRequestTrigger_UE_TZ_CH,
}

func SnssaiHexToModels(hexString string) (*models.Snssai, error) {
	sst, err := strconv.ParseInt(hexString[:2], 16, 32)
	if err != nil {
		return nil, err
	}
	sNssai := models.Snssai{
		Sst: int32(sst),
		Sd:  hexString[2:],
	}
	return &sNssai, nil
}

func SnssaiModelsToHex(snssai models.Snssai) string {
	sst := fmt.Sprintf("%02x", snssai.Sst)
	return sst + snssai.Sd
}

func SeperateAmfId(amfid string) (regionId, setId, ptrId string, err error) {
	if len(amfid) != 6 {
		err = fmt.Errorf("len of amfId[%s] != 6", amfid)
		return
	}
	// regionId: 16bits, setId: 10bits, ptrId: 6bits
	regionId = amfid[:2]
	byteArray, err1 := hex.DecodeString(amfid[2:])
	if err1 != nil {
		err = err1
		return
	}
	byteSetId := []byte{byteArray[0] >> 6, byteArray[0]<<2 | byteArray[1]>>6}
	setId = hex.EncodeToString(byteSetId)[1:]
	bytePtrId := []byte{byteArray[1] & 0x3f}
	ptrId = hex.EncodeToString(bytePtrId)
	return
}

func PlmnIdStringToModels(plmnId string) (plmnID models.PlmnId) {
	plmnID.Mcc = plmnId[:3]
	plmnID.Mnc = plmnId[3:]
	return
}

func TACConfigToModels(intString string) (hexString string) {
	tmp, err := strconv.ParseUint(intString, 10, 32)
	if err != nil {
		logger.UtilLog.Errorf("ParseUint error: %+v", err)
	}
	hexString = fmt.Sprintf("%06x", tmp)
	return
}

// 20241125 add for PC5
// Use BitMap to generate requested policy control triggers,
// 1 means yes, 0 means no, see subscaulse 5.6.3.6-1 in TS29512
func PolicyControlReqTrigToArray(bitMap uint64) (trigger []models.PolicyControlRequestTrigger) {
	cnt := 0
	size := len(policyTriggerArray)
	for bitMap > 0 && cnt < size {
		if (bitMap & 0x01) > 0 {
			trigger = append(trigger, policyTriggerArray[cnt])
		}
		bitMap >>= 1
		cnt++
	}
	return
}
