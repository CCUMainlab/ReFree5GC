package context

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/oauth"
	"github.com/free5gc/sdpaf/internal/logger"
	"github.com/free5gc/sdpaf/pkg/factory"
	"github.com/free5gc/util/idgenerator"

	"os"

	"github.com/google/uuid"
)

type AUSFContext struct {
	suciSupiMap          sync.Map
	UePool               sync.Map
	NfId                 string
	GroupID              string
	SBIPort              int
	RegisterIPv4         string
	BindingIPv4          string
	Url                  string
	UriScheme            models.UriScheme
	NrfUri               string
	NrfCertPem           string
	NfService            map[models.ServiceName]models.NfService
	PlmnList             []models.PlmnId
	UdmUeauUrl           string
	snRegex              *regexp.Regexp
	EapAkaSupiImsiPrefix bool
	OAuth2Required       bool

	// 20250107 add for PCF
	PcfServiceUris  map[models.ServiceName]string
	Locality        string
	Name            string
	TimeFormat      string
	DefaultBdtRefId string
	UePool_PCF      sync.Map
	// App Session related
	AppSessionPool sync.Map
	PcfSuppFeats   map[models.ServiceName]openapi.SupportedFeature
	// AMF Status Change Subscription related
	AMFStatusSubsData sync.Map // map[string]AMFStatusSubscriptionData; subscriptionID as key

	// lock
	DefaultUdrURILock sync.RWMutex

	// Charging
	RatingGroupIdGenerator *idgenerator.IDGenerator

	// Bdt Policy related
	BdtPolicyPool        sync.Map
	BdtPolicyIDGenerator *idgenerator.IDGenerator
	DefaultUdrURI        string

	// 20250114 add for UDM
	UdmUePool                      sync.Map // map[supi]*UdmUeContext
	EeSubscriptionIDGenerator      *idgenerator.IDGenerator
	SharedSubsDataMap              map[string]models.SharedData // sharedDataIds as key
	SubscriptionOfSharedDataChange sync.Map                     // subscriptionID as key
}

type AusfUeContext struct {
	Supi               string
	Kausf              string
	Kseaf              string
	ServingNetworkName string
	AuthStatus         models.AuthResult
	UdmUeauUrl         string

	// for 5G AKA
	XresStar string

	// for EAP-AKA'
	K_aut    string
	XRES     string
	Rand     string
	EapID    uint8
	Resynced bool

	// 20250114 add for UDM
	Gpsi                              string
	EeSubscriptions                   map[string]*models.EeSubscription // subscriptionID as key
	ExternalGroupID                   string
	UdrUri                            string
	UdmSubsToNotify                   map[string]*models.SubscriptionDataSubscriptions
	SubscribeToNotifChange            map[string]*models.SdmSubscription
	Amf3GppAccessRegistration         *models.Amf3GppAccessRegistration
	AmfNon3GppAccessRegistration      *models.AmfNon3GppAccessRegistration
	amSubsDataLock                    sync.Mutex
	AccessAndMobilitySubscriptionData *models.AccessAndMobilitySubscriptionData
	SubsDataSets                      *models.SubscriptionDataSets
	SmfSelSubsData                    *models.SmfSelectionSubscriptionData
	smfSelSubsDataLock                sync.Mutex
	UeCtxtInSmfData                   *models.UeContextInSmfData
	SmSubsDataLock                    sync.RWMutex
	SessionManagementSubsData         map[string]models.SessionManagementSubscriptionData
	TraceData                         *models.TraceData
	TraceDataResponse                 models.TraceDataResponse
	Nssai                             *models.Nssai
}

type SuciSupiMap struct {
	SupiOrSuci string
	Supi       string
}

type EapAkaPrimeAttribute struct {
	Type   uint8
	Length uint8
	Value  []byte
}

type EapAkaPrimePkt struct {
	Subtype    uint8
	Attributes map[uint8]EapAkaPrimeAttribute
	MACInput   []byte
}

const (
	EAP_AKA_PRIME_TYPENUM = 50
)

// Attribute Types for EAP-AKA'
const (
	AT_RAND_ATTRIBUTE              = 1
	AT_AUTN_ATTRIBUTE              = 2
	AT_RES_ATTRIBUTE               = 3
	AT_AUTS_ATTRIBUTE              = 4
	AT_MAC_ATTRIBUTE               = 11
	AT_NOTIFICATION_ATTRIBUTE      = 12
	AT_IDENTITY_ATTRIBUTE          = 14
	AT_CLIENT_ERROR_CODE_ATTRIBUTE = 22
	AT_KDF_INPUT_ATTRIBUTE         = 23
	AT_KDF_ATTRIBUTE               = 24
)

// Subtypes for EAP-AKA'
const (
	AKA_CHALLENGE_SUBTYPE               = 1
	AKA_AUTHENTICATION_REJECT_SUBTYPE   = 2
	AKA_SYNCHRONIZATION_FAILURE_SUBTYPE = 4
	AKA_NOTIFICATION_SUBTYPE            = 12
	AKA_CLIENT_ERROR_SUBTYPE            = 14
)

var ausfContext AUSFContext

const (
	LocationUriAmf3GppAccessRegistration int = iota
	LocationUriAmfNon3GppAccessRegistration
	LocationUriSmfRegistration
	LocationUriSdmSubscription
	LocationUriSharedDataSubscription
)

func Init() {
	if snRegex, err := regexp.Compile("5G:mnc[0-9]{3}[.]mcc[0-9]{3}[.]3gppnetwork[.]org"); err != nil {
		logger.CtxLog.Warnf("SN compile error: %+v", err)
	} else {
		ausfContext.snRegex = snRegex
	}

	// Initialize RatingGroupIdGenerator
	ausfContext.RatingGroupIdGenerator = idgenerator.NewGenerator(1, math.MaxInt32)

	ausfContext.NfService = make(map[models.ServiceName]models.NfService)
	InitAusfContext(&ausfContext)

	// Init PCF related
	// ausfContext.Name = "pcf"
	// ausfContext.UriScheme = models.UriScheme_HTTPS
	// ausfContext.TimeFormat = "2006-01-02 15:04:05"
	// ausfContext.DefaultBdtRefId = "BdtPolicyId-"
	// ausfContext.NfService = make(map[models.ServiceName]models.NfService)
	// ausfContext.PcfServiceUris = make(map[models.ServiceName]string)
	// ausfContext.PcfSuppFeats = make(map[models.ServiceName]openapi.SupportedFeature)
	// ausfContext.BdtPolicyIDGenerator = idgenerator.NewGenerator(1, math.MaxInt64)
	// ausfContext.RatingGroupIdGenerator = idgenerator.NewGenerator(1, math.MaxInt64)
	// InitPcfContext(&ausfContext)
}

func InitPcfContext(context *AUSFContext) {
	config := factory.AusfConfig
	logger.UtilLog.Infof("pcfconfig Info: Version[%s] Description[%s]", config.Info.Version, config.Info.Description)
	configuration := config.Configuration
	context.NfId = uuid.New().String()
	if configuration.PcfName != "" {
		context.Name = configuration.PcfName
	}

	// mongodb := config.Configuration.Mongodb
	// // Connect to MongoDB
	// if err := mongoapi.SetMongoDB(mongodb.Name, mongodb.Url); err != nil {
	// 	logger.UtilLog.Errorf("InitpcfContext err: %+v", err)
	// 	return
	// }

	sbi := configuration.Sbi
	context.NrfUri = configuration.NrfUri
	context.NrfCertPem = configuration.NrfCertPem
	context.UriScheme = ""
	context.RegisterIPv4 = factory.AusfSbiDefaultIPv4 // default localhost
	context.SBIPort = factory.AusfSbiDefaultPort      // default port
	if sbi != nil {
		if sbi.Scheme != "" {
			context.UriScheme = models.UriScheme(sbi.Scheme)
		}
		if sbi.RegisterIPv4 != "" {
			context.RegisterIPv4 = sbi.RegisterIPv4
		}
		if sbi.Port != 0 {
			context.SBIPort = sbi.Port
		}
		if sbi.Scheme == "https" {
			context.UriScheme = models.UriScheme_HTTPS
		} else {
			context.UriScheme = models.UriScheme_HTTP
		}

		context.BindingIPv4 = os.Getenv(sbi.BindingIPv4)
		if context.BindingIPv4 != "" {
			logger.UtilLog.Info("Parsing ServerIPv4 address from ENV Variable.")
		} else {
			context.BindingIPv4 = sbi.BindingIPv4
			if context.BindingIPv4 == "" {
				logger.UtilLog.Warn("Error parsing ServerIPv4 address as string. Using the 0.0.0.0 address as default.")
				context.BindingIPv4 = "0.0.0.0"
			}
		}
	}
	serviceList := configuration.ServiceList
	context.InitNFService(serviceList, config.Info.Version)
	context.TimeFormat = configuration.TimeFormat
	context.DefaultBdtRefId = configuration.DefaultBdtRefId
	for _, service := range context.NfService {
		var err error
		context.PcfServiceUris[service.ServiceName] = service.ApiPrefix +
			"/" + string(service.ServiceName) + "/" + (*service.Versions)[0].ApiVersionInUri
		context.PcfSuppFeats[service.ServiceName], err = openapi.NewSupportedFeature(service.SupportedFeatures)
		if err != nil {
			logger.UtilLog.Errorf("openapi NewSupportedFeature error: %+v", err)
		}
	}
	context.Locality = configuration.Locality
}

type NFContext interface {
	AuthorizationCheck(token string, serviceName models.ServiceName) error
}

var _ NFContext = &AUSFContext{}

func NewAusfUeContext(identifier string) (ausfUeContext *AusfUeContext) {
	ausfUeContext = new(AusfUeContext)
	ausfUeContext.Supi = identifier // supi
	return ausfUeContext
}

func AddAusfUeContextToPool(ausfUeContext *AusfUeContext) {
	ausfContext.UePool.Store(ausfUeContext.Supi, ausfUeContext)
}

func CheckIfAusfUeContextExists(ref string) bool {
	_, ok := ausfContext.UePool.Load(ref)
	return ok
}

func GetAusfUeContext(ref string) *AusfUeContext {
	context, _ := ausfContext.UePool.Load(ref)
	ausfUeContext := context.(*AusfUeContext)
	return ausfUeContext
}

func AddSuciSupiPairToMap(supiOrSuci string, supi string) {
	newPair := new(SuciSupiMap)
	newPair.SupiOrSuci = supiOrSuci
	newPair.Supi = supi
	ausfContext.suciSupiMap.Store(supiOrSuci, newPair)
}

func CheckIfSuciSupiPairExists(ref string) bool {
	_, ok := ausfContext.suciSupiMap.Load(ref)
	return ok
}

func GetSupiFromSuciSupiMap(ref string) (supi string) {
	val, _ := ausfContext.suciSupiMap.Load(ref)
	suciSupiMap := val.(*SuciSupiMap)
	supi = suciSupiMap.Supi
	return supi
}

func IsServingNetworkAuthorized(lookup string) bool {
	if ausfContext.snRegex.MatchString(lookup) {
		return true
	} else {
		return false
	}
}

func GetSelf() *AUSFContext {
	return &ausfContext
}

func (a *AUSFContext) GetSelfID() string {
	return a.NfId
}

func (c *AUSFContext) GetTokenCtx(serviceName models.ServiceName, targetNF models.NfType) (
	context.Context, *models.ProblemDetails, error,
) {
	if !c.OAuth2Required {
		return context.TODO(), nil, nil
	}
	return oauth.GetTokenCtx(models.NfType_AUSF, targetNF,
		c.NfId, c.NrfUri, string(serviceName))
}

func (c *AUSFContext) AuthorizationCheck(token string, serviceName models.ServiceName) error {
	if !c.OAuth2Required {
		logger.UtilLog.Debugf("AUSFContext::AuthorizationCheck: OAuth2 not required\n")
		return nil
	}

	logger.UtilLog.Debugf("AUSFContext::AuthorizationCheck: token[%s] serviceName[%s]\n", token, serviceName)
	return oauth.VerifyOAuth(token, string(serviceName), c.NrfCertPem)
}

// 20250107 add for PCF
type AMFStatusSubscriptionData struct {
	AmfUri       string
	AmfStatusUri string
	GuamiList    []models.Guami
}

func GetUri(name models.ServiceName) string {
	return ausfContext.PcfServiceUris[name]
}

type AppSessionData struct {
	AppSessionId      string
	AppSessionContext *models.AppSessionContext
	// (compN/compN-subCompN/appId-%s) map to PccRule
	RelatedPccRuleIds    map[string]string
	PccRuleIdMapToCompId map[string]string
	// EventSubscription
	Events   map[models.AfEvent]models.AfNotifMethod
	EventUri string
	// related Session
	SmPolicyData *UeSmPolicyData
}

// Find PcfUe which the policyId belongs to
func (c *AUSFContext) PCFUeFindByPolicyId(PolicyId string) *UeContext {
	index := strings.LastIndex(PolicyId, "-")
	if index == -1 {
		return nil
	}
	supi := PolicyId[:index]
	if supi != "" {
		if value, ok := c.UePool_PCF.Load(supi); ok {
			ueContext := value.(*UeContext)
			return ueContext
		}
	}
	return nil
}

// Allocate PCF Ue with supi and add to pcf Context and returns allocated ue
func (c *AUSFContext) NewPCFUe(Supi string) (*UeContext, error) {
	if strings.HasPrefix(Supi, "imsi-") {
		newUeContext := &UeContext{}
		newUeContext.SmPolicyData = make(map[string]*UeSmPolicyData)
		newUeContext.AMPolicyData = make(map[string]*UeAMPolicyData)
		newUeContext.PolAssociationIDGenerator = 1
		newUeContext.AppSessionIDGenerator = idgenerator.NewGenerator(1, math.MaxInt64)
		newUeContext.Supi = Supi
		c.UePool_PCF.Store(Supi, newUeContext)
		return newUeContext, nil
	} else {
		return nil, fmt.Errorf(" add Ue context fail ")
	}
}

// Find PcfUe which the AppSessionId belongs to
func (c *AUSFContext) PCFUeFindByAppSessionId(appSessionId string) *UeContext {
	index := strings.LastIndex(appSessionId, "-")
	if index == -1 {
		return nil
	}
	supi := appSessionId[:index]
	if supi != "" {
		if value, ok := c.UePool_PCF.Load(supi); ok {
			ueContext := value.(*UeContext)
			return ueContext
		}
	}
	return nil
}

// Find PcfUe which Ipv4 belongs to
func (c *AUSFContext) PcfUeFindByIPv4(v4 string) *UeContext {
	var ue *UeContext
	c.UePool_PCF.Range(func(key, value interface{}) bool {
		ue = value.(*UeContext)
		if ue.SMPolicyFindByIpv4(v4) != nil {
			return false
		} else {
			return true
		}
	})

	return ue
}

// Find PcfUe which Ipv6 belongs to
func (c *AUSFContext) PcfUeFindByIPv6(v6 string) *UeContext {
	var ue *UeContext
	c.UePool_PCF.Range(func(key, value interface{}) bool {
		ue = value.(*UeContext)
		if ue.SMPolicyFindByIpv6(v6) != nil {
			return false
		} else {
			return true
		}
	})

	return ue
}

func (c *AUSFContext) GetIPv4Uri() string {
	return fmt.Sprintf("%s://%s:%d", c.UriScheme, c.RegisterIPv4, c.SBIPort)
}

func (c *AUSFContext) NewAmfStatusSubscription(subscriptionID string, subscriptionData AMFStatusSubscriptionData) {
	c.AMFStatusSubsData.Store(subscriptionID, subscriptionData)
}

// Find SMPolicy with AppSessionContext
func ueSMPolicyFindByAppSessionContext(ue *UeContext, req *models.AppSessionContextReqData) (*UeSmPolicyData, error) {
	var policy *UeSmPolicyData
	var err error

	if req.UeIpv4 != "" {
		policy = ue.SMPolicyFindByIdentifiersIpv4(req.UeIpv4, req.SliceInfo, req.Dnn, req.IpDomain)
		if policy == nil {
			err = fmt.Errorf("can't find ue with ipv4[%s]", req.UeIpv4)
		}
	} else if req.UeIpv6 != "" {
		policy = ue.SMPolicyFindByIdentifiersIpv6(req.UeIpv6, req.SliceInfo, req.Dnn)
		if policy == nil {
			err = fmt.Errorf("can't find ue with ipv6 prefix[%s]", req.UeIpv6)
		}
	} else {
		err = fmt.Errorf("ue finding by MAC address does not support")
	}
	return policy, err
}

// SessionBinding from application request to get corresponding Sm policy
func (c *AUSFContext) SessionBinding(req *models.AppSessionContextReqData) (*UeSmPolicyData, error) {
	var selectedUE *UeContext
	var policy *UeSmPolicyData
	var err error

	if req.Supi != "" {
		if val, exist := c.UePool_PCF.Load(req.Supi); exist {
			selectedUE = val.(*UeContext)
		}
	}

	if req.Gpsi != "" && selectedUE == nil {
		c.UePool_PCF.Range(func(key, value interface{}) bool {
			ue := value.(*UeContext)
			if ue.Gpsi == req.Gpsi {
				selectedUE = ue
				return false
			} else {
				return true
			}
		})
	}

	if selectedUE != nil {
		policy, err = ueSMPolicyFindByAppSessionContext(selectedUE, req)
	} else {
		c.UePool_PCF.Range(func(key, value interface{}) bool {
			ue := value.(*UeContext)
			policy, err = ueSMPolicyFindByAppSessionContext(ue, req)
			return true
		})
	}
	if policy == nil && err == nil {
		err = fmt.Errorf("no SM policy found")
	}
	return policy, err
}

// SetDefaultUdrURI ... function to set DefaultUdrURI
func (c *AUSFContext) SetDefaultUdrURI(uri string) {
	c.DefaultUdrURILock.Lock()
	defer c.DefaultUdrURILock.Unlock()
	c.DefaultUdrURI = uri
}

// Return Bdt Policy Id with format "BdtPolicyId-%d" which be allocated
func (c *AUSFContext) AllocBdtPolicyID() (bdtPolicyID string, err error) {
	var allocID int64
	if allocID, err = c.BdtPolicyIDGenerator.Allocate(); err != nil {
		logger.CtxLog.Warnf("Allocate pathID error: %+v", err)
		return "", err
	}

	bdtPolicyID = fmt.Sprintf("BdtPolicyId-%d", allocID)
	return bdtPolicyID, nil
}

var (
	PolicyAuthorizationUri       = factory.PcfPolicyAuthResUriPrefix + "/app-sessions/"
	SmUri                        = factory.PcfSMpolicyCtlResUriPrefix
	IPv4Address                  = "192.168."
	IPv6Address                  = "ffab::"
	PolicyDataChangeNotifyUri    = factory.PcfCallbackResUriPrefix + "/nudr-notify/policy-data"
	InfluenceDataUpdateNotifyUri = factory.PcfCallbackResUriPrefix + "/nudr-notify/influence-data"
	Ipv4_pool                    = make(map[string]string)
	Ipv6_pool                    = make(map[string]string)
)

// 20250114 add for UDM
func (context *AUSFContext) UdmUeFindByGpsi(gpsi string) (*AusfUeContext, bool) {
	var ue *AusfUeContext
	ok := false
	context.UdmUePool.Range(func(key, value interface{}) bool {
		candidate := value.(*AusfUeContext)
		if candidate.Gpsi == gpsi {
			ue = candidate
			ok = true
			return false
		}
		return true
	})
	return ue, ok
}

func (context *AUSFContext) UdmUeFindBySupi(supi string) (*AusfUeContext, bool) {
	if value, ok := context.UdmUePool.Load(supi); ok {
		return value.(*AusfUeContext), ok
	} else {
		return nil, false
	}
}

func (ue *AusfUeContext) Init() {
	ue.UdmSubsToNotify = make(map[string]*models.SubscriptionDataSubscriptions)
	ue.EeSubscriptions = make(map[string]*models.EeSubscription)
	ue.SubscribeToNotifChange = make(map[string]*models.SdmSubscription)
}

func (context *AUSFContext) NewUdmUe(supi string) *AusfUeContext {
	ue := new(AusfUeContext)
	ue.Init()
	ue.Supi = supi
	context.UdmUePool.Store(supi, ue)
	return ue
}

// Function to set the AccessAndMobilitySubscriptionData for Ue
func (udmUeContext *AusfUeContext) SetAMSubsriptionData(amData *models.AccessAndMobilitySubscriptionData) {
	udmUeContext.amSubsDataLock.Lock()
	defer udmUeContext.amSubsDataLock.Unlock()
	udmUeContext.AccessAndMobilitySubscriptionData = amData
}

// Returns the  SUPI from the SUPI list (SUPI list contains either a SUPI or a NAI)
func GetCorrespondingSupi(list models.IdentityData) (id string) {
	var identifier string
	for i := 0; i < len(list.SupiList); i++ {
		if strings.Contains(list.SupiList[i], "imsi") {
			identifier = list.SupiList[i]
		}
	}
	return identifier
}

// functions related to Retrieval of multiple datasets(GetSupi)
func (context *AUSFContext) CreateSubsDataSetsForUe(supi string, body models.SubscriptionDataSets) {
	ue, ok := context.UdmUeFindBySupi(supi)
	if !ok {
		ue = context.NewUdmUe(supi)
	}
	ue.SubsDataSets = &body
}

// Function to create the AccessAndMobilitySubscriptionData for Ue
func (context *AUSFContext) CreateAccessMobilitySubsDataForUe(supi string,
	body models.AccessAndMobilitySubscriptionData,
) {
	ue, ok := context.UdmUeFindBySupi(supi)
	if !ok {
		ue = context.NewUdmUe(supi)
	}
	ue.AccessAndMobilitySubscriptionData = &body
}

// functions for SmfSelectionSubscriptionData
func (context *AUSFContext) CreateSmfSelectionSubsDataforUe(supi string, body models.SmfSelectionSubscriptionData) {
	ue, ok := context.UdmUeFindBySupi(supi)
	if !ok {
		ue = context.NewUdmUe(supi)
	}
	ue.SmfSelSubsData = &body
}

// SetSmfSelectionSubsData ... functions to set SmfSelectionSubscriptionData
func (udmUeContext *AusfUeContext) SetSmfSelectionSubsData(smfSelSubsData *models.SmfSelectionSubscriptionData) {
	udmUeContext.smfSelSubsDataLock.Lock()
	defer udmUeContext.smfSelSubsDataLock.Unlock()
	udmUeContext.SmfSelSubsData = smfSelSubsData
}

// functions related UecontextInSmfData
func (context *AUSFContext) CreateUeContextInSmfDataforUe(supi string, body models.UeContextInSmfData) {
	ue, ok := context.UdmUeFindBySupi(supi)
	if !ok {
		ue = context.NewUdmUe(supi)
	}
	ue.UeCtxtInSmfData = &body
}

func (context *AUSFContext) ManageSmData(smDatafromUDR []models.SessionManagementSubscriptionData, snssaiFromReq string,
	dnnFromReq string) (mp map[string]models.SessionManagementSubscriptionData, ind string,
	Dnns []models.DnnConfiguration, allDnns []map[string]models.DnnConfiguration,
) {
	smDataMap := make(map[string]models.SessionManagementSubscriptionData)
	sNssaiList := make([]string, len(smDatafromUDR))
	// to obtain all DNN configurations identified by "dnn" for all network slices where such DNN is available
	AllDnnConfigsbyDnn := make([]models.DnnConfiguration, len(sNssaiList))
	// to obtain all DNN configurations for all network slice(s)
	AllDnns := make([]map[string]models.DnnConfiguration, len(smDatafromUDR))
	var snssaikey string // Required snssai to obtain all DNN configurations

	for idx, smSubscriptionData := range smDatafromUDR {
		singleNssaiStr := openapi.MarshToJsonString(smSubscriptionData.SingleNssai)[0]
		smDataMap[singleNssaiStr] = smSubscriptionData
		// sNssaiList = append(sNssaiList, singleNssaiStr)
		AllDnns[idx] = smSubscriptionData.DnnConfigurations
		if strings.Contains(singleNssaiStr, snssaiFromReq) {
			snssaikey = singleNssaiStr
		}

		if _, ok := smSubscriptionData.DnnConfigurations[dnnFromReq]; ok {
			AllDnnConfigsbyDnn = append(AllDnnConfigsbyDnn, smSubscriptionData.DnnConfigurations[dnnFromReq])
		}
	}

	return smDataMap, snssaikey, AllDnnConfigsbyDnn, AllDnns
}

// SetSMSubsData ... functions to set SessionManagementSubsData
func (udmUeContext *AusfUeContext) SetSMSubsData(smSubsData map[string]models.SessionManagementSubscriptionData) {
	udmUeContext.SmSubsDataLock.Lock()
	defer udmUeContext.SmSubsDataLock.Unlock()
	udmUeContext.SessionManagementSubsData = smSubsData
}

// Functions related to the trace data configuration
func (context *AUSFContext) CreateTraceDataforUe(supi string, body models.TraceData) {
	ue, ok := context.UdmUeFindBySupi(supi)
	if !ok {
		ue = context.NewUdmUe(supi)
	}
	ue.TraceData = &body
}

// HandleGetSharedData related functions
func MappingSharedData(sharedDatafromUDR []models.SharedData) (mp map[string]models.SharedData) {
	sharedSubsDataMap := make(map[string]models.SharedData)
	for i := 0; i < len(sharedDatafromUDR); i++ {
		sharedSubsDataMap[sharedDatafromUDR[i].SharedDataId] = sharedDatafromUDR[i]
	}
	return sharedSubsDataMap
}

func ObtainRequiredSharedData(Sharedids []string, response []models.SharedData) (sharedDatas []models.SharedData) {
	sharedSubsDataMap := MappingSharedData(response)
	Allkeys := make([]string, len(sharedSubsDataMap))
	MatchedKeys := make([]string, len(Sharedids))
	counter := 0
	for k := range sharedSubsDataMap {
		Allkeys = append(Allkeys, k)
	}

	for j := 0; j < len(Sharedids); j++ {
		for i := 0; i < len(Allkeys); i++ {
			if strings.Contains(Allkeys[i], Sharedids[j]) {
				MatchedKeys[counter] = Allkeys[i]
			}
		}
		counter += 1
	}

	shared_Data := make([]models.SharedData, len(MatchedKeys))
	if len(MatchedKeys) != 1 {
		for i := 0; i < len(MatchedKeys); i++ {
			shared_Data[i] = sharedSubsDataMap[MatchedKeys[i]]
		}
	} else {
		shared_Data[0] = sharedSubsDataMap[MatchedKeys[0]]
	}
	return shared_Data
}

// TODO: this function has wrong UE pool key with subscriptionID
func (context *AUSFContext) CreateSubstoNotifSharedData(subscriptionID string, body *models.SdmSubscription) {
	context.SubscriptionOfSharedDataChange.Store(subscriptionID, body)
}

// GetSDMUri ... get subscriber data management service uri
func (context *AUSFContext) GetSDMUri() string {
	return context.GetIPv4Uri() + factory.UdmSdmResUriPrefix
}

// functions related to sdmSubscription (subscribe to notification of data change)
func (udmUeContext *AusfUeContext) CreateSubscriptiontoNotifChange(subscriptionID string, body *models.SdmSubscription) {
	if _, exist := udmUeContext.SubscribeToNotifChange[subscriptionID]; !exist {
		udmUeContext.SubscribeToNotifChange[subscriptionID] = body
	}
}

func (ue *AusfUeContext) GetLocationURI2(types int, supi string) string {
	switch types {
	case LocationUriSharedDataSubscription:
		// return GetSelf().GetIPv4Uri() + UdmSdmResUriPrefix +"/shared-data-subscriptions/" + nf.SubscriptionID
	case LocationUriSdmSubscription:
		return GetSelf().GetIPv4Uri() + factory.UdmSdmResUriPrefix + "/" + supi + "/sdm-subscriptions/"
	}
	return ""
}
