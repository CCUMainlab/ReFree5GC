package consumer

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	udm_context "github.com/free5gc/cpaf/internal/context"
	"github.com/free5gc/cpaf/internal/logger"
	"github.com/free5gc/cpaf/internal/util"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/Nudr_DataRepository"
	"github.com/free5gc/openapi/models"
)

type nudrService struct {
	consumer *Consumer

	nfDRMu sync.RWMutex

	nfDRClients map[string]*Nudr_DataRepository.APIClient
}

const (
	NFDiscoveryToUDRParamNone int = iota
	NFDiscoveryToUDRParamSupi
	NFDiscoveryToUDRParamExtGroupId
	NFDiscoveryToUDRParamGpsi
)

func (s *nudrService) CreateUDMClientToUDR(id string) (*Nudr_DataRepository.APIClient, error) {
	uri := s.getUdrURI(id)
	if uri == "" {
		logger.ProcLog.Errorf("ID[%s] does not match any UDR", id)
		return nil, fmt.Errorf("No UDR URI found")
	}
	s.nfDRMu.RLock()
	client, ok := s.nfDRClients[uri]
	if ok {
		s.nfDRMu.RUnlock()
		return client, nil
	}

	cfg := Nudr_DataRepository.NewConfiguration()
	cfg.SetBasePath(uri)
	client = Nudr_DataRepository.NewAPIClient(cfg)

	s.nfDRMu.RUnlock()
	s.nfDRMu.Lock()
	defer s.nfDRMu.Unlock()
	s.nfDRClients[uri] = client
	return client, nil
}

func (s *nudrService) getUdrURI(id string) string {
	if strings.Contains(id, "imsi") || strings.Contains(id, "nai") { // supi
		ue, ok := udm_context.GetSelf().UdmUeFindBySupi(id)
		if ok {
			if ue.UdrUri == "" {
				ue.UdrUri = SendNFIntancesUDR(id, NFDiscoveryToUDRParamSupi)
			}
			return ue.UdrUri
		} else {
			ue = udm_context.GetSelf().NewUdmUe(id)
			ue.UdrUri = SendNFIntancesUDR(id, NFDiscoveryToUDRParamSupi)
			return ue.UdrUri
		}
	} else if strings.Contains(id, "pei") {
		var udrURI string
		udm_context.GetSelf().UdmUePool.Range(func(key, value interface{}) bool {
			ue := value.(*udm_context.UdmUeContext)
			if ue.Amf3GppAccessRegistration != nil && ue.Amf3GppAccessRegistration.Pei == id {
				if ue.UdrUri == "" {
					ue.UdrUri = SendNFIntancesUDR(ue.Supi, NFDiscoveryToUDRParamSupi)
				}
				udrURI = ue.UdrUri
				return false
			} else if ue.AmfNon3GppAccessRegistration != nil && ue.AmfNon3GppAccessRegistration.Pei == id {
				if ue.UdrUri == "" {
					ue.UdrUri = SendNFIntancesUDR(ue.Supi, NFDiscoveryToUDRParamSupi)
				}
				udrURI = ue.UdrUri
				return false
			}
			return true
		})
		return udrURI
	} else if strings.Contains(id, "extgroupid") {
		// extra group id
		return SendNFIntancesUDR(id, NFDiscoveryToUDRParamExtGroupId)
	} else if strings.Contains(id, "msisdn") || strings.Contains(id, "extid") {
		// gpsi
		return SendNFIntancesUDR(id, NFDiscoveryToUDRParamGpsi)
	}
	return SendNFIntancesUDR("", NFDiscoveryToUDRParamNone)
}

// 20241125 add for PC5
// 添加 CreateInfluenceDataSubscription 相關方法
func (s *nudrService) CreateInfluenceDataSubscription(ue *udm_context.UeContext, request models.SmPolicyContextData) (
	subscriptionID string, problemDetails *models.ProblemDetails, err error,
) {
	if ue.UdrUri == "" {
		problemDetail := util.GetProblemDetail("Can't find corresponding UDR with UE", util.USER_UNKNOWN)
		logger.ConsumerLog.Warnf("Can't find corresponding UDR with UE[%s]", ue.Supi)
		return "", &problemDetail, nil
	}

	ctx, pd, err := s.consumer.Context().GetTokenCtx(models.ServiceName_NUDR_DR, models.NfType_UDR)
	if err != nil {
		return "", pd, err
	}

	client, err := s.CreateUDMClientToUDR(ue.Supi)
	if err != nil {
		return "", nil, err
	}

	trafficInfluSub := s.buildTrafficInfluSub(request)
	_, httpResp, localErr := client.InfluenceDataSubscriptionsCollectionApi.
		ApplicationDataInfluenceDataSubsToNotifyPost(ctx, trafficInfluSub)

	if localErr == nil {
		locationHeader := httpResp.Header.Get("Location")
		subscriptionID = locationHeader[strings.LastIndex(locationHeader, "/")+1:]
		logger.ConsumerLog.Debugf("Influence Data Subscription ID: %s", subscriptionID)
		return subscriptionID, nil, nil
	} else if httpResp != nil {
		defer func() {
			if rspCloseErr := httpResp.Body.Close(); rspCloseErr != nil {
				logger.ConsumerLog.Errorf("CreateInfluenceDataSubscription response body cannot close: %+v",
					rspCloseErr)
			}
		}()
		if httpResp.Status != localErr.Error() {
			err = localErr
			return subscriptionID, problemDetails, err
		}
		problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		err = openapi.ReportError("server no response")
	}
	return "", problemDetails, err
}

func (s *nudrService) buildTrafficInfluSub(request models.SmPolicyContextData) models.TrafficInfluSub {
	trafficInfluSub := models.TrafficInfluSub{
		Dnns:             []string{request.Dnn},
		Snssais:          []models.Snssai{*request.SliceInfo},
		InternalGroupIds: request.InterGrpIds,
		Supis:            []string{request.Supi},
		NotificationUri: s.consumer.Context().GetIPv4Uri() +
			"/npcf-callback/v1/nudr-notify/influence-data" + "/" +
			request.Supi + "/" + strconv.Itoa(int(request.PduSessionId)),
	}
	return trafficInfluSub
}

func (s *nudrService) RemoveInfluenceDataSubscription(ue *udm_context.UeContext, subscriptionID string) (
	problemDetails *models.ProblemDetails, err error,
) {
	if ue.UdrUri == "" {
		problemDetail := util.GetProblemDetail("Can't find corresponding UDR with UE", util.USER_UNKNOWN)
		logger.ConsumerLog.Warnf("Can't find corresponding UDR with UE[%s]", ue.Supi)
		return &problemDetail, nil
	}

	ctx, pd, err := s.consumer.Context().GetTokenCtx(models.ServiceName_NUDR_DR, models.NfType_UDR)
	if err != nil {
		return pd, err
	}

	client, err := s.CreateUDMClientToUDR(ue.Supi)
	if err != nil {
		return nil, err
	}

	httpResp, localErr := client.IndividualInfluenceDataSubscriptionDocumentApi.
		ApplicationDataInfluenceDataSubsToNotifySubscriptionIdDelete(ctx, subscriptionID)

	if localErr == nil {
		logger.ConsumerLog.Debugf("Nudr_DataRepository Remove Influence Data Subscription Status %s",
			httpResp.Status)
	} else if httpResp != nil {
		defer func() {
			if rspCloseErr := httpResp.Body.Close(); rspCloseErr != nil {
				logger.ConsumerLog.Errorf("RemoveInfluenceDataSubscription response body cannot close: %+v",
					rspCloseErr)
			}
		}()
		if httpResp.Status != localErr.Error() {
			err = localErr
			return problemDetails, err
		}
		problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		err = openapi.ReportError("server no response")
	}
	return problemDetails, err
}
