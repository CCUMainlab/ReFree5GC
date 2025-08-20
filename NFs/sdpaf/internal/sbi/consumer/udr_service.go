package consumer

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/Nudr_DataRepository"
	"github.com/free5gc/openapi/models"
	sdpaf_context "github.com/free5gc/sdpaf/internal/context"
	"github.com/free5gc/sdpaf/internal/logger"
	"github.com/free5gc/sdpaf/internal/util"
)

type nudrService struct {
	consumer *Consumer

	nfDataSubMu sync.RWMutex

	nfDataSubClients map[string]*Nudr_DataRepository.APIClient

	// 20250114 add for UDM
	nfDRMu      sync.RWMutex
	nfDRClients map[string]*Nudr_DataRepository.APIClient
}

const (
	NFDiscoveryToUDRParamNone int = iota
	NFDiscoveryToUDRParamSupi
	NFDiscoveryToUDRParamExtGroupId
	NFDiscoveryToUDRParamGpsi
)

func (s *nudrService) getDataSubscription(uri string) *Nudr_DataRepository.APIClient {
	if uri == "" {
		return nil
	}
	s.nfDataSubMu.RLock()
	client, ok := s.nfDataSubClients[uri]
	if ok {
		defer s.nfDataSubMu.RUnlock()
		return client
	}

	configuration := Nudr_DataRepository.NewConfiguration()
	configuration.SetBasePath(uri)
	client = Nudr_DataRepository.NewAPIClient(configuration)

	s.nfDataSubMu.RUnlock()
	s.nfDataSubMu.Lock()
	defer s.nfDataSubMu.Unlock()
	s.nfDataSubClients[uri] = client
	return client
}

func (s *nudrService) CreateInfluenceDataSubscription(ue *sdpaf_context.UeContext, request models.SmPolicyContextData) (
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
	client := s.getDataSubscription(ue.UdrUri)
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
			sdpaf_context.InfluenceDataUpdateNotifyUri + "/" +
			request.Supi + "/" + strconv.Itoa(int(request.PduSessionId)),
		// TODO: support expiry time and resend subscription when expired
	}
	return trafficInfluSub
}

func (s *nudrService) RemoveInfluenceDataSubscription(ue *sdpaf_context.UeContext, subscriptionID string) (
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
	client := s.getDataSubscription(ue.UdrUri)
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

func (s *nudrService) CreateUDMClientToUDR(id string) (*Nudr_DataRepository.APIClient, error) {
	uri := s.getUdrURI(id)
	if uri == "" {
		logger.ProcLog.Errorf("ID[%s] does not match any UDR", id)
		return nil, fmt.Errorf("no UDR URI found")
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
		ue, ok := sdpaf_context.GetSelf().UdmUeFindBySupi(id)
		if ok {
			if ue.UdrUri == "" {
				ue.UdrUri = SendNFIntancesUDR(id, NFDiscoveryToUDRParamSupi)
			}
			return ue.UdrUri
		} else {
			ue = sdpaf_context.GetSelf().NewUdmUe(id)
			ue.UdrUri = SendNFIntancesUDR(id, NFDiscoveryToUDRParamSupi)
			return ue.UdrUri
		}
	} else if strings.Contains(id, "pei") {
		var udrURI string
		sdpaf_context.GetSelf().UdmUePool.Range(func(key, value interface{}) bool {
			ue := value.(*sdpaf_context.AusfUeContext)
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
