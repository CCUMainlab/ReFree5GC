package context

import (
	"context"
	"fmt"
	"math"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/free5gc/cpaf/internal/logger"
	"github.com/free5gc/cpaf/pkg/factory"
	"github.com/free5gc/nas/nasConvert"
	"github.com/free5gc/nas/security"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/oauth"
	"github.com/free5gc/util/idgenerator"

	"github.com/free5gc/openapi/Nnrf_NFDiscovery"
	"github.com/free5gc/udm/pkg/suci"

	"github.com/free5gc/util/mongoapi"
)

var (
	amfContext                       AMFContext
	tmsiGenerator                    *idgenerator.IDGenerator = nil
	amfUeNGAPIDGenerator             *idgenerator.IDGenerator = nil
	amfStatusSubscriptionIDGenerator *idgenerator.IDGenerator = nil
)

const (
	LocationUriAmf3GppAccessRegistration int = iota
	LocationUriAmfNon3GppAccessRegistration
	LocationUriSmfRegistration
	LocationUriSdmSubscription
	LocationUriSharedDataSubscription
)

func init() {
	GetSelf().LadnPool = make(map[string]factory.Ladn)
	GetSelf().EventSubscriptionIDGenerator = idgenerator.NewGenerator(1, math.MaxInt32)
	GetSelf().Name = "amf"
	GetSelf().UriScheme = models.UriScheme_HTTPS
	GetSelf().RelativeCapacity = 0xff
	GetSelf().ServedGuamiList = make([]models.Guami, 0, MaxNumOfServedGuamiList)
	GetSelf().PlmnSupportList = make([]factory.PlmnSupportItem, 0, MaxNumOfPLMNs)
	GetSelf().NfService = make(map[models.ServiceName]models.NfService)
	GetSelf().NetworkName.Full = "free5GC"
	tmsiGenerator = idgenerator.NewGenerator(1, math.MaxInt32)
	amfStatusSubscriptionIDGenerator = idgenerator.NewGenerator(1, math.MaxInt32)
	amfUeNGAPIDGenerator = idgenerator.NewGenerator(1, MaxValueOfAmfUeNgapId)

	// 20241107 add for UD3
	GetSelf().EeSubscriptionIDGenerator = idgenerator.NewGenerator(1, math.MaxInt32)

	// 20241119 add for PC5
	GetSelf().TimeFormat = "2006-01-02 15:04:05"
	GetSelf().DefaultBdtRefId = "BdtPolicyId-"
	GetSelf().PcfServiceUris = make(map[models.ServiceName]string)
	GetSelf().PcfSuppFeats = make(map[models.ServiceName]openapi.SupportedFeature)
	GetSelf().BdtPolicyIDGenerator = idgenerator.NewGenerator(1, math.MaxInt64)
	GetSelf().RatingGroupIdGenerator = idgenerator.NewGenerator(1, math.MaxInt64)
}

type NFContext interface {
	AuthorizationCheck(token string, serviceName models.ServiceName) error
}

var _ NFContext = &AMFContext{}

type AMFContext struct {
	EventSubscriptionIDGenerator *idgenerator.IDGenerator
	EventSubscriptions           sync.Map
	UePool                       sync.Map                // map[supi]*AmfUe
	RanUePool                    sync.Map                // map[AmfUeNgapID]*RanUe
	AmfRanPool                   sync.Map                // map[net.Conn]*AmfRan
	LadnPool                     map[string]factory.Ladn // dnn as key
	SupportTaiLists              []models.Tai
	ServedGuamiList              []models.Guami
	PlmnSupportList              []factory.PlmnSupportItem
	RelativeCapacity             int64
	NfId                         string
	Name                         string
	NfService                    map[models.ServiceName]models.NfService // nfservice that amf support
	UriScheme                    models.UriScheme
	BindingIPv4                  string
	SBIPort                      int
	RegisterIPv4                 string
	HttpIPv6Address              string
	TNLWeightFactor              int64
	SupportDnnLists              []string
	AMFStatusSubscriptions       sync.Map // map[subscriptionID]models.SubscriptionData
	NrfUri                       string
	NrfCertPem                   string
	SecurityAlgorithm            SecurityAlgorithm
	NetworkName                  factory.NetworkName
	NgapIpList                   []string // NGAP Server IP
	NgapPort                     int
	T3502Value                   int    // unit is second
	T3512Value                   int    // unit is second
	Non3gppDeregTimerValue       int    // unit is second
	TimeZone                     string // "[+-]HH:MM[+][1-2]", Refer to TS 29.571 - 5.2.2 Simple Data Types
	// read-only fields
	T3513Cfg factory.TimerValue
	T3522Cfg factory.TimerValue
	T3550Cfg factory.TimerValue
	T3560Cfg factory.TimerValue
	T3565Cfg factory.TimerValue
	T3570Cfg factory.TimerValue
	T3555Cfg factory.TimerValue
	Locality string

	OAuth2Required bool

	//20241107 add for UD3
	GroupId                        string
	NFDiscoveryClient              *Nnrf_NFDiscovery.APIClient
	UdmUePool                      sync.Map // map[supi]*UdmUeContext
	GpsiSupiList                   models.IdentityData
	SharedSubsDataMap              map[string]models.SharedData // sharedDataIds as key
	SubscriptionOfSharedDataChange sync.Map                     // subscriptionID as key
	SuciProfiles                   []suci.SuciProfile
	EeSubscriptionIDGenerator      *idgenerator.IDGenerator

	// 20241119 add for PC5
	TimeFormat             string
	DefaultBdtRefId        string
	PcfServiceUris         map[models.ServiceName]string
	PcfSuppFeats           map[models.ServiceName]openapi.SupportedFeature
	DefaultUdrURI          string
	BdtPolicyPool          sync.Map
	BdtPolicyIDGenerator   *idgenerator.IDGenerator
	AppSessionPool         sync.Map
	AMFStatusSubsData      sync.Map // map[string]AMFStatusSubscriptionData
	DefaultUdrURILock      sync.RWMutex
	RatingGroupIdGenerator *idgenerator.IDGenerator
}

// 20241107 add for UD3
type UdmUeContext struct {
	Supi                              string
	Gpsi                              string
	ExternalGroupID                   string
	Nssai                             *models.Nssai
	Amf3GppAccessRegistration         *models.Amf3GppAccessRegistration
	AmfNon3GppAccessRegistration      *models.AmfNon3GppAccessRegistration
	AccessAndMobilitySubscriptionData *models.AccessAndMobilitySubscriptionData
	SmfSelSubsData                    *models.SmfSelectionSubscriptionData
	UeCtxtInSmfData                   *models.UeContextInSmfData
	TraceDataResponse                 models.TraceDataResponse
	TraceData                         *models.TraceData
	SessionManagementSubsData         map[string]models.SessionManagementSubscriptionData
	SubsDataSets                      *models.SubscriptionDataSets
	SubscribeToNotifChange            map[string]*models.SdmSubscription
	SubscribeToNotifSharedDataChange  *models.SdmSubscription
	PduSessionID                      string
	UdrUri                            string
	UdmSubsToNotify                   map[string]*models.SubscriptionDataSubscriptions
	EeSubscriptions                   map[string]*models.EeSubscription // subscriptionID as key
	amSubsDataLock                    sync.Mutex
	smfSelSubsDataLock                sync.Mutex
	SmSubsDataLock                    sync.RWMutex
}

// 20241107 add for UD3
func (ue *UdmUeContext) Init() {
	ue.UdmSubsToNotify = make(map[string]*models.SubscriptionDataSubscriptions)
	ue.EeSubscriptions = make(map[string]*models.EeSubscription)
	ue.SubscribeToNotifChange = make(map[string]*models.SdmSubscription)
}

// 20241107 add for UD3
type UdmNFContext struct {
	SubscriptionID                   string
	SubscribeToNotifChange           *models.SdmSubscription // SubscriptionID as key
	SubscribeToNotifSharedDataChange *models.SdmSubscription // SubscriptionID as key
}

// 20241119 add for pc5
type AMFStatusSubscriptionData struct {
	AmfUri       string
	AmfStatusUri string
	GuamiList    []models.Guami
}

type AppSessionData struct {
	AppSessionId         string
	AppSessionContext    *models.AppSessionContext
	RelatedPccRuleIds    map[string]string
	PccRuleIdMapToCompId map[string]string
	Events               map[models.AfEvent]models.AfNotifMethod
	EventUri             string
	SmPolicyData         *UeSmPolicyData
}

type AMFContextEventSubscription struct {
	IsAnyUe           bool
	IsGroupUe         bool
	UeSupiList        []string
	Expiry            *time.Time
	EventSubscription models.AmfEventSubscription
}

type SecurityAlgorithm struct {
	IntegrityOrder []uint8 // slice of security.AlgIntegrityXXX
	CipheringOrder []uint8 // slice of security.AlgCipheringXXX
}

func InitAmfContext(context *AMFContext) {
	config := factory.AmfConfig
	logger.UtilLog.Infof("amfconfig Info: Version[%s]", config.GetVersion())
	configuration := config.Configuration
	context.NfId = uuid.New().String()
	if configuration.AmfName != "" {
		context.Name = configuration.AmfName
	}
	if configuration.NgapIpList != nil {
		context.NgapIpList = configuration.NgapIpList
	} else {
		context.NgapIpList = []string{"127.0.0.1"} // default localhost
	}
	context.NgapPort = config.GetNgapPort()
	context.UriScheme = models.UriScheme(config.GetSbiScheme())
	context.RegisterIPv4 = config.GetSbiRegisterIP()
	context.SBIPort = config.GetSbiPort()
	context.BindingIPv4 = config.GetSbiBindingIP()

	context.InitNFService(config.GetServiceNameList(), config.GetVersion())
	context.ServedGuamiList = configuration.ServedGumaiList
	context.SupportTaiLists = configuration.SupportTAIList
	context.PlmnSupportList = configuration.PlmnSupportList
	context.SupportDnnLists = configuration.SupportDnnList
	for _, ladn := range configuration.SupportLadnList {
		context.LadnPool[ladn.Dnn] = ladn
	}
	context.NrfUri = config.GetNrfUri()
	context.NrfCertPem = configuration.NrfCertPem
	security := configuration.Security
	if security != nil {
		context.SecurityAlgorithm.IntegrityOrder = getIntAlgOrder(security.IntegrityOrder)
		context.SecurityAlgorithm.CipheringOrder = getEncAlgOrder(security.CipheringOrder)
	}
	context.NetworkName = configuration.NetworkName
	context.TimeZone = nasConvert.GetTimeZone(time.Now())
	context.T3502Value = configuration.T3502Value
	context.T3512Value = configuration.T3512Value
	context.Non3gppDeregTimerValue = configuration.Non3gppDeregTimerValue
	context.T3513Cfg = configuration.T3513
	context.T3522Cfg = configuration.T3522
	context.T3550Cfg = configuration.T3550
	context.T3560Cfg = configuration.T3560
	context.T3565Cfg = configuration.T3565
	context.T3570Cfg = configuration.T3570
	context.T3555Cfg = configuration.T3555
	context.Locality = configuration.Locality

	// 20241111 add for ud3
	context.SharedSubsDataMap = make(map[string]models.SharedData)
	context.SuciProfiles = configuration.SuciProfiles
	servingNameList := configuration.ServiceNameList
	context.InitNFService(servingNameList, config.GetVersion())

	// 20241119 add for pc5
	mongodb := config.Configuration.Mongodb
	if mongodb != nil {
		// Connect to MongoDB
		if err := mongoapi.SetMongoDB(mongodb.Name, mongodb.Url); err != nil {
			logger.UtilLog.Errorf("InitContext err: %+v", err)
			return
		}
	}

	context.TimeFormat = config.Configuration.TimeFormat
	context.DefaultBdtRefId = config.Configuration.DefaultBdtRefId

	// 初始化 PCF service URIs 和 features
	for _, service := range context.NfService {
		serviceName := service.ServiceName
		context.PcfServiceUris[serviceName] = service.ApiPrefix +
			"/" + string(serviceName) + "/" + (*service.Versions)[0].ApiVersionInUri

		var err error
		context.PcfSuppFeats[serviceName], err = openapi.NewSupportedFeature(service.SupportedFeatures)
		if err != nil {
			logger.UtilLog.Errorf("openapi NewSupportedFeature error: %+v", err)
		}
	}
}

func getIntAlgOrder(integrityOrder []string) (intOrder []uint8) {
	for _, intAlg := range integrityOrder {
		switch intAlg {
		case "NIA0":
			intOrder = append(intOrder, security.AlgIntegrity128NIA0)
		case "NIA1":
			intOrder = append(intOrder, security.AlgIntegrity128NIA1)
		case "NIA2":
			intOrder = append(intOrder, security.AlgIntegrity128NIA2)
		case "NIA3":
			intOrder = append(intOrder, security.AlgIntegrity128NIA3)
		default:
			logger.UtilLog.Errorf("Unsupported algorithm: %s", intAlg)
		}
	}
	return
}

func getEncAlgOrder(cipheringOrder []string) (encOrder []uint8) {
	for _, encAlg := range cipheringOrder {
		switch encAlg {
		case "NEA0":
			encOrder = append(encOrder, security.AlgCiphering128NEA0)
		case "NEA1":
			encOrder = append(encOrder, security.AlgCiphering128NEA1)
		case "NEA2":
			encOrder = append(encOrder, security.AlgCiphering128NEA2)
		case "NEA3":
			encOrder = append(encOrder, security.AlgCiphering128NEA3)
		default:
			logger.UtilLog.Errorf("Unsupported algorithm: %s", encAlg)
		}
	}
	return
}

func NewPlmnSupportItem() (item factory.PlmnSupportItem) {
	item.SNssaiList = make([]models.Snssai, 0, MaxNumOfSlice)
	return
}

func (context *AMFContext) TmsiAllocate() int32 {
	tmsi, err := tmsiGenerator.Allocate()
	if err != nil {
		logger.CtxLog.Errorf("Allocate TMSI error: %+v", err)
		return -1
	}
	return int32(tmsi)
}

func (context *AMFContext) FreeTmsi(tmsi int64) {
	tmsiGenerator.FreeID(tmsi)
}

func (context *AMFContext) AllocateAmfUeNgapID() (int64, error) {
	return amfUeNGAPIDGenerator.Allocate()
}

func (context *AMFContext) AllocateGutiToUe(ue *AmfUe) {
	servedGuami := context.ServedGuamiList[0]
	ue.Tmsi = context.TmsiAllocate()

	plmnID := servedGuami.PlmnId.Mcc + servedGuami.PlmnId.Mnc
	tmsiStr := fmt.Sprintf("%08x", ue.Tmsi)
	ue.Guti = plmnID + servedGuami.AmfId + tmsiStr
}

func (context *AMFContext) AllocateRegistrationArea(ue *AmfUe, anType models.AccessType) {
	// clear the previous registration area if need
	if len(ue.RegistrationArea[anType]) > 0 {
		ue.RegistrationArea[anType] = nil
	}

	// allocate a new tai list as a registration area to ue
	// TODO: algorithm to choose TAI list
	for _, supportTai := range context.SupportTaiLists {
		if reflect.DeepEqual(supportTai, ue.Tai) {
			ue.RegistrationArea[anType] = append(ue.RegistrationArea[anType], supportTai)
			break
		}
	}
}

func (context *AMFContext) NewAMFStatusSubscription(subscriptionData models.SubscriptionData) (subscriptionID string) {
	id, err := amfStatusSubscriptionIDGenerator.Allocate()
	if err != nil {
		logger.CtxLog.Errorf("Allocate subscriptionID error: %+v", err)
		return ""
	}

	subscriptionID = strconv.Itoa(int(id))
	context.AMFStatusSubscriptions.Store(subscriptionID, subscriptionData)
	return
}

// Return Value: (subscriptionData *models.SubScriptionData, ok bool)
func (context *AMFContext) FindAMFStatusSubscription(subscriptionID string) (*models.SubscriptionData, bool) {
	if value, ok := context.AMFStatusSubscriptions.Load(subscriptionID); ok {
		subscriptionData := value.(models.SubscriptionData)
		return &subscriptionData, ok
	} else {
		return nil, false
	}
}

func (context *AMFContext) DeleteAMFStatusSubscription(subscriptionID string) {
	context.AMFStatusSubscriptions.Delete(subscriptionID)
	if id, err := strconv.ParseInt(subscriptionID, 10, 64); err != nil {
		logger.CtxLog.Error(err)
	} else {
		amfStatusSubscriptionIDGenerator.FreeID(id)
	}
}

func (context *AMFContext) NewEventSubscription(subscriptionID string, subscription *AMFContextEventSubscription) {
	context.EventSubscriptions.Store(subscriptionID, subscription)
}

func (context *AMFContext) FindEventSubscription(subscriptionID string) (*AMFContextEventSubscription, bool) {
	if value, ok := context.EventSubscriptions.Load(subscriptionID); ok {
		return value.(*AMFContextEventSubscription), ok
	} else {
		return nil, false
	}
}

func (context *AMFContext) DeleteEventSubscription(subscriptionID string) {
	context.EventSubscriptions.Delete(subscriptionID)
	if id, err := strconv.ParseInt(subscriptionID, 10, 32); err != nil {
		logger.CtxLog.Error(err)
	} else {
		context.EventSubscriptionIDGenerator.FreeID(id)
	}
}

func (context *AMFContext) AddAmfUeToUePool(ue *AmfUe, supi string) {
	if len(supi) == 0 {
		logger.CtxLog.Errorf("Supi is nil")
	}
	ue.Supi = supi
	context.UePool.Store(ue.Supi, ue)
}

func (context *AMFContext) NewAmfUe(supi string) *AmfUe {
	ue := AmfUe{}
	ue.init()

	if supi != "" {
		context.AddAmfUeToUePool(&ue, supi)
	}

	context.AllocateGutiToUe(&ue)

	logger.CtxLog.Infof("New AmfUe [supi:%s][guti:%s]", supi, ue.Guti)
	return &ue
}

func (context *AMFContext) AmfUeFindByUeContextID(ueContextID string) (*AmfUe, bool) {
	if strings.HasPrefix(ueContextID, "imsi") {
		return context.AmfUeFindBySupi(ueContextID)
	}
	if strings.HasPrefix(ueContextID, "imei") {
		return context.AmfUeFindByPei(ueContextID)
	}
	if strings.HasPrefix(ueContextID, "5g-guti") {
		guti := ueContextID[strings.LastIndex(ueContextID, "-")+1:]
		return context.AmfUeFindByGuti(guti)
	}
	return nil, false
}

func (context *AMFContext) AmfUeFindBySupi(supi string) (*AmfUe, bool) {
	if value, ok := context.UePool.Load(supi); ok {
		return value.(*AmfUe), ok
	}
	return nil, false
}

func (context *AMFContext) AmfUeFindBySuci(suci string) (ue *AmfUe, ok bool) {
	context.UePool.Range(func(key, value interface{}) bool {
		candidate := value.(*AmfUe)
		if ok = (candidate.Suci == suci); ok {
			ue = candidate
			return false
		}
		return true
	})
	return
}

func (context *AMFContext) AmfUeFindByPei(pei string) (*AmfUe, bool) {
	var ue *AmfUe
	var ok bool
	context.UePool.Range(func(key, value interface{}) bool {
		candidate := value.(*AmfUe)
		if ok = (candidate.Pei == pei); ok {
			ue = candidate
			return false
		}
		return true
	})
	return ue, ok
}

func (context *AMFContext) NewAmfRan(conn net.Conn) *AmfRan {
	ran := AmfRan{}
	ran.SupportedTAList = make([]SupportedTAI, 0, MaxNumOfTAI*MaxNumOfBroadcastPLMNs)
	ran.Conn = conn
	addr := conn.RemoteAddr()
	if addr != nil {
		ran.Log = logger.NgapLog.WithField(logger.FieldRanAddr, addr.String())
	} else {
		ran.Log = logger.NgapLog.WithField(logger.FieldRanAddr, "(nil)")
	}

	context.AmfRanPool.Store(conn, &ran)
	return &ran
}

// use net.Conn to find RAN context, return *AmfRan and ok bit
func (context *AMFContext) AmfRanFindByConn(conn net.Conn) (*AmfRan, bool) {
	if value, ok := context.AmfRanPool.Load(conn); ok {
		return value.(*AmfRan), ok
	}
	return nil, false
}

// use ranNodeID to find RAN context, return *AmfRan and ok bit
func (context *AMFContext) AmfRanFindByRanID(ranNodeID models.GlobalRanNodeId) (*AmfRan, bool) {
	var ran *AmfRan
	var ok bool
	context.AmfRanPool.Range(func(key, value interface{}) bool {
		amfRan := value.(*AmfRan)
		if amfRan.RanId == nil {
			return true
		}

		switch amfRan.RanPresent {
		case RanPresentGNbId:
			if amfRan.RanId.GNbId != nil && ranNodeID.GNbId != nil &&
				amfRan.RanId.GNbId.GNBValue == ranNodeID.GNbId.GNBValue {
				ran = amfRan
				ok = true
				return false
			}
		case RanPresentNgeNbId:
			if amfRan.RanId.NgeNbId == ranNodeID.NgeNbId {
				ran = amfRan
				ok = true
				return false
			}
		case RanPresentN3IwfId:
			if amfRan.RanId.N3IwfId == ranNodeID.N3IwfId {
				ran = amfRan
				ok = true
				return false
			}
		}
		return true
	})
	return ran, ok
}

func (context *AMFContext) DeleteAmfRan(conn net.Conn) {
	context.AmfRanPool.Delete(conn)
}

func (context *AMFContext) InSupportDnnList(targetDnn string) bool {
	for _, dnn := range context.SupportDnnLists {
		if dnn == targetDnn {
			return true
		}
	}
	return false
}

func (context *AMFContext) InPlmnSupportList(snssai models.Snssai) bool {
	for _, plmnSupportItem := range context.PlmnSupportList {
		for _, supportSnssai := range plmnSupportItem.SNssaiList {
			if openapi.SnssaiEqualFold(supportSnssai, snssai) {
				return true
			}
		}
	}
	return false
}

func (context *AMFContext) AmfUeFindByGuti(guti string) (*AmfUe, bool) {
	var ue *AmfUe
	var ok bool
	context.UePool.Range(func(key, value interface{}) bool {
		candidate := value.(*AmfUe)
		if ok = (candidate.Guti == guti); ok {
			ue = candidate
			return false
		}
		return true
	})
	return ue, ok
}

func (context *AMFContext) AmfUeFindByPolicyAssociationID(polAssoId string) (*AmfUe, bool) {
	var ue *AmfUe
	var ok bool
	context.UePool.Range(func(key, value interface{}) bool {
		candidate := value.(*AmfUe)
		if ok = (candidate.PolicyAssociationId == polAssoId); ok {
			ue = candidate
			return false
		}
		return true
	})
	return ue, ok
}

func (context *AMFContext) RanUeFindByAmfUeNgapID(amfUeNgapID int64) *RanUe {
	if value, ok := context.RanUePool.Load(amfUeNgapID); ok {
		return value.(*RanUe)
	}
	return nil
}

func (context *AMFContext) GetIPv4Uri() string {
	return fmt.Sprintf("%s://%s:%d", context.UriScheme, context.RegisterIPv4, context.SBIPort)
}

func (context *AMFContext) InitNFService(serivceName []string, version string) {
	tmpVersion := strings.Split(version, ".")
	versionUri := "v" + tmpVersion[0]
	for index, nameString := range serivceName {
		name := models.ServiceName(nameString)
		context.NfService[name] = models.NfService{
			ServiceInstanceId: strconv.Itoa(index),
			ServiceName:       name,
			Versions: &[]models.NfServiceVersion{
				{
					ApiFullVersion:  version,
					ApiVersionInUri: versionUri,
				},
			},
			Scheme:          context.UriScheme,
			NfServiceStatus: models.NfServiceStatus_REGISTERED,
			ApiPrefix:       context.GetIPv4Uri(),
			IpEndPoints: &[]models.IpEndPoint{
				{
					Ipv4Address: context.RegisterIPv4,
					Transport:   models.TransportProtocol_TCP,
					Port:        int32(context.SBIPort),
				},
			},
		}
	}
}

// Reset AMF Context
func (context *AMFContext) Reset() {
	context.AmfRanPool.Range(func(key, value interface{}) bool {
		context.UePool.Delete(key)
		return true
	})
	for key := range context.LadnPool {
		delete(context.LadnPool, key)
	}
	context.RanUePool.Range(func(key, value interface{}) bool {
		context.RanUePool.Delete(key)
		return true
	})
	context.UePool.Range(func(key, value interface{}) bool {
		context.UePool.Delete(key)
		return true
	})
	context.EventSubscriptions.Range(func(key, value interface{}) bool {
		context.DeleteEventSubscription(key.(string))
		return true
	})
	for key := range context.NfService {
		delete(context.NfService, key)
	}
	context.SupportTaiLists = context.SupportTaiLists[:0]
	context.PlmnSupportList = context.PlmnSupportList[:0]
	context.ServedGuamiList = context.ServedGuamiList[:0]
	context.RelativeCapacity = 0xff
	context.NfId = ""
	context.UriScheme = models.UriScheme_HTTPS
	context.SBIPort = 0
	context.BindingIPv4 = ""
	context.RegisterIPv4 = ""
	context.HttpIPv6Address = ""
	context.Name = "amf"
	context.NrfUri = ""
	context.NrfCertPem = ""
	context.OAuth2Required = false
}

// Create new AMF context
func GetSelf() *AMFContext {
	return &amfContext
}

func (c *AMFContext) GetTokenCtx(serviceName models.ServiceName, targetNF models.NfType) (
	context.Context, *models.ProblemDetails, error,
) {
	if !c.OAuth2Required {
		return context.TODO(), nil, nil
	}
	return oauth.GetTokenCtx(models.NfType_AMF, targetNF,
		c.NfId, c.NrfUri, string(serviceName))
}

func (c *AMFContext) AuthorizationCheck(token string, serviceName models.ServiceName) error {
	if !c.OAuth2Required {
		logger.UtilLog.Debugf("AMFContext::AuthorizationCheck: OAuth2 not required\n")
		return nil
	}

	logger.UtilLog.Debugf("AMFContext::AuthorizationCheck: token[%s] serviceName[%s]\n", token, serviceName)
	return oauth.VerifyOAuth(token, string(serviceName), c.NrfCertPem)
}

// UDM 相關方法

func (context *AMFContext) NewUdmUe(supi string) *UdmUeContext {
	ue := new(UdmUeContext)
	ue.Init()
	ue.Supi = supi
	context.UdmUePool.Store(supi, ue)
	return ue
}

func (context *AMFContext) UdmUeFindBySupi(supi string) (*UdmUeContext, bool) {
	if value, ok := context.UdmUePool.Load(supi); ok {
		return value.(*UdmUeContext), ok
	}
	return nil, false
}

func (context *AMFContext) UdmUeFindByGpsi(gpsi string) (*UdmUeContext, bool) {
	var ue *UdmUeContext
	ok := false
	context.UdmUePool.Range(func(key, value interface{}) bool {
		candidate := value.(*UdmUeContext)
		if candidate.Gpsi == gpsi {
			ue = candidate
			ok = true
			return false
		}
		return true
	})
	return ue, ok
}

func (context *AMFContext) CreateAccessMobilitySubsDataForUe(supi string, body models.AccessAndMobilitySubscriptionData) {
	ue, ok := context.UdmUeFindBySupi(supi)
	if !ok {
		ue = context.NewUdmUe(supi)
	}
	ue.AccessAndMobilitySubscriptionData = &body
}

func (context *AMFContext) CreateSubsDataSetsForUe(supi string, body models.SubscriptionDataSets) {
	ue, ok := context.UdmUeFindBySupi(supi)
	if !ok {
		ue = context.NewUdmUe(supi)
	}
	ue.SubsDataSets = &body
}

func (context *AMFContext) CreateTraceDataforUe(supi string, body models.TraceData) {
	ue, ok := context.UdmUeFindBySupi(supi)
	if !ok {
		ue = context.NewUdmUe(supi)
	}
	ue.TraceData = &body
}

func (udmUeContext *UdmUeContext) CreateSubscriptiontoNotifChange(subscriptionID string, body *models.SdmSubscription) {
	if _, exist := udmUeContext.SubscribeToNotifChange[subscriptionID]; !exist {
		udmUeContext.SubscribeToNotifChange[subscriptionID] = body
	}
}

func (context *AMFContext) CreateSubstoNotifSharedData(subscriptionID string, body *models.SdmSubscription) {
	context.SubscriptionOfSharedDataChange.Store(subscriptionID, body)
}

func (context *AMFContext) ManageSmData(smDatafromUDR []models.SessionManagementSubscriptionData,
	snssaiFromReq string, dnnFromReq string) (mp map[string]models.SessionManagementSubscriptionData,
	ind string, Dnns []models.DnnConfiguration, allDnns []map[string]models.DnnConfiguration) {

	smDataMap := make(map[string]models.SessionManagementSubscriptionData)
	sNssaiList := make([]string, len(smDatafromUDR))
	AllDnnConfigsbyDnn := make([]models.DnnConfiguration, len(sNssaiList))
	AllDnns := make([]map[string]models.DnnConfiguration, len(smDatafromUDR))
	var snssaikey string

	for idx, smSubscriptionData := range smDatafromUDR {
		singleNssaiStr := openapi.MarshToJsonString(smSubscriptionData.SingleNssai)[0]
		smDataMap[singleNssaiStr] = smSubscriptionData
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

func (context *AMFContext) GetSDMUri() string {
	return context.GetIPv4Uri() + factory.UdmSdmResUriPrefix
}

func (ue *UdmUeContext) GetLocationURI(types int) string {
	switch types {
	case LocationUriAmf3GppAccessRegistration:
		return GetSelf().GetIPv4Uri() + factory.UdmUecmResUriPrefix + "/" + ue.Supi + "/registrations/amf-3gpp-access"
	case LocationUriAmfNon3GppAccessRegistration:
		return GetSelf().GetIPv4Uri() + factory.UdmUecmResUriPrefix + "/" + ue.Supi + "/registrations/amf-non-3gpp-access"
	case LocationUriSmfRegistration:
		return GetSelf().GetIPv4Uri() + factory.UdmUecmResUriPrefix + "/" + ue.Supi + "/registrations/smf-registrations/" + ue.PduSessionID
	}
	return ""
}

func (ue *UdmUeContext) GetLocationURI2(types int, supi string) string {
	switch types {
	case LocationUriSdmSubscription:
		return GetSelf().GetIPv4Uri() + factory.UdmSdmResUriPrefix + "/" + supi + "/sdm-subscriptions/"
	}
	return ""
}

func (ue *UdmUeContext) SameAsStoredGUAMI3gpp(inGuami models.Guami) bool {
	if ue.Amf3GppAccessRegistration == nil {
		return false
	}
	ug := ue.Amf3GppAccessRegistration.Guami
	if ug != nil {
		if (ug.PlmnId == nil) == (inGuami.PlmnId == nil) {
			if ug.PlmnId != nil && ug.PlmnId.Mcc == inGuami.PlmnId.Mcc && ug.PlmnId.Mnc == inGuami.PlmnId.Mnc {
				if ug.AmfId == inGuami.AmfId {
					return true
				}
			}
		}
	}
	return false
}

func (ue *UdmUeContext) SameAsStoredGUAMINon3gpp(inGuami models.Guami) bool {
	if ue.AmfNon3GppAccessRegistration == nil {
		return false
	}
	ug := ue.AmfNon3GppAccessRegistration.Guami
	if ug != nil {
		if (ug.PlmnId == nil) == (inGuami.PlmnId == nil) {
			if ug.PlmnId != nil && ug.PlmnId.Mcc == inGuami.PlmnId.Mcc && ug.PlmnId.Mnc == inGuami.PlmnId.Mnc {
				if ug.AmfId == inGuami.AmfId {
					return true
				}
			}
		}
	}
	return false
}

// Shared Data相關方法
func MappingSharedData(sharedDatafromUDR []models.SharedData) (mp map[string]models.SharedData) {
	sharedSubsDataMap := make(map[string]models.SharedData)
	for i := 0; i < len(sharedDatafromUDR); i++ {
		sharedSubsDataMap[sharedDatafromUDR[i].SharedDataId] = sharedDatafromUDR[i]
	}
	return sharedSubsDataMap
}

func GetCorrespondingSupi(list models.IdentityData) (id string) {
	var identifier string
	for i := 0; i < len(list.SupiList); i++ {
		if strings.Contains(list.SupiList[i], "imsi") {
			identifier = list.SupiList[i]
		}
	}
	return identifier
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

// 20241119 add for pc5
// PCF Related Methods

// AllocBdtPolicyID - Return Bdt Policy Id with format "BdtPolicyId-%d"
func (context *AMFContext) AllocBdtPolicyID() (bdtPolicyID string, err error) {
	var allocID int64
	if allocID, err = context.BdtPolicyIDGenerator.Allocate(); err != nil {
		logger.CtxLog.Warnf("Allocate pathID error: %+v", err)
		return "", err
	}
	bdtPolicyID = fmt.Sprintf("BdtPolicyId-%d", allocID)
	return bdtPolicyID, nil
}

// PCF UE Finding Methods

// PCFUeFindByPolicyId - Find PCF UE by policy ID
func (context *AMFContext) PCFUeFindByPolicyId(PolicyId string) *UeContext {
	index := strings.LastIndex(PolicyId, "-")
	if index == -1 {
		return nil
	}
	supi := PolicyId[:index]
	if supi != "" {
		if value, ok := context.UePool.Load(supi); ok {
			ueContext := value.(*UeContext)
			return ueContext
		}
	}
	return nil
}

// PCFUeFindByAppSessionId - Find PCF UE by AppSession ID
func (context *AMFContext) PCFUeFindByAppSessionId(appSessionId string) *UeContext {
	index := strings.LastIndex(appSessionId, "-")
	if index == -1 {
		return nil
	}
	supi := appSessionId[:index]
	if supi != "" {
		if value, ok := context.UePool.Load(supi); ok {
			ueContext := value.(*UeContext)
			return ueContext
		}
	}
	return nil
}

// IP Pool Related Const and Vars
var (
	IPv4Address                  = "192.168."
	IPv6Address                  = "ffab::"
	Ipv4_pool                    = make(map[string]string)
	Ipv6_pool                    = make(map[string]string)
	PolicyAuthorizationUri       = factory.PcfPolicyAuthResUriPrefix + "/app-sessions/"
	SmUri                        = factory.PcfSMpolicyCtlResUriPrefix
	PolicyDataChangeNotifyUri    = factory.PcfCallbackResUriPrefix + "/nudr-notify/policy-data"
	InfluenceDataUpdateNotifyUri = factory.PcfCallbackResUriPrefix + "/nudr-notify/influence-data"
)

// IP Pool Management Methods

func Ipv4Pool(ipindex int32) string {
	ipv4address := IPv4Address + fmt.Sprint((int(ipindex)/255)+1) + "." + fmt.Sprint(int(ipindex)%255)
	return ipv4address
}

func Ipv4Index() int32 {
	if len(Ipv4_pool) == 0 {
		Ipv4_pool["1"] = Ipv4Pool(1)
	} else {
		for i := 1; i <= len(Ipv4_pool); i++ {
			if Ipv4_pool[fmt.Sprint(i)] == "" {
				Ipv4_pool[fmt.Sprint(i)] = Ipv4Pool(int32(i))
				return int32(i)
			}
		}
		Ipv4_pool[fmt.Sprint(int32(len(Ipv4_pool)+1))] = Ipv4Pool(int32(len(Ipv4_pool) + 1))
		return int32(len(Ipv4_pool))
	}
	return 1
}

func GetIpv4Address(ipindex int32) string {
	return Ipv4_pool[fmt.Sprint(ipindex)]
}

func DeleteIpv4index(Ipv4index int32) {
	delete(Ipv4_pool, fmt.Sprint(Ipv4index))
}

func Ipv6Pool(ipindex int32) string {
	ipv6address := IPv6Address + fmt.Sprintf("%x\n", ipindex)
	return ipv6address
}

func Ipv6Index() int32 {
	if len(Ipv6_pool) == 0 {
		Ipv6_pool["1"] = Ipv6Pool(1)
	} else {
		for i := 1; i <= len(Ipv6_pool); i++ {
			if Ipv6_pool[fmt.Sprint(i)] == "" {
				Ipv6_pool[fmt.Sprint(i)] = Ipv6Pool(int32(i))
				return int32(i)
			}
		}
		Ipv6_pool[fmt.Sprint(int32(len(Ipv6_pool)+1))] = Ipv6Pool(int32(len(Ipv6_pool) + 1))
		return int32(len(Ipv6_pool))
	}
	return 1
}

func GetIpv6Address(ipindex int32) string {
	return Ipv6_pool[fmt.Sprint(ipindex)]
}

func DeleteIpv6index(Ipv6index int32) {
	delete(Ipv6_pool, fmt.Sprint(Ipv6index))
}

// Session Management Methods

func (context *AMFContext) SessionBinding(req *models.AppSessionContextReqData) (*UeSmPolicyData, error) {
	var selectedUE *UeContext
	var policy *UeSmPolicyData
	var err error

	if req.Supi != "" {
		if val, exist := context.UePool.Load(req.Supi); exist {
			selectedUE = val.(*UeContext)
		}
	}

	if req.Gpsi != "" && selectedUE == nil {
		context.UePool.Range(func(key, value interface{}) bool {
			ue := value.(*UeContext)
			if ue.Gpsi == req.Gpsi {
				selectedUE = ue
				return false
			}
			return true
		})
	}

	if selectedUE != nil {
		policy, err = ueSMPolicyFindByAppSessionContext(selectedUE, req)
	} else {
		context.UePool.Range(func(key, value interface{}) bool {
			ue := value.(*UeContext)
			policy, err = ueSMPolicyFindByAppSessionContext(ue, req)
			return true
		})
	}
	if policy == nil && err == nil {
		err = fmt.Errorf("No SM policy found")
	}
	return policy, err
}

// Helper function for SessionBinding
func ueSMPolicyFindByAppSessionContext(ue *UeContext, req *models.AppSessionContextReqData) (*UeSmPolicyData, error) {
	var policy *UeSmPolicyData
	var err error

	if req.UeIpv4 != "" {
		policy = ue.SMPolicyFindByIdentifiersIpv4(req.UeIpv4, req.SliceInfo, req.Dnn, req.IpDomain)
		if policy == nil {
			err = fmt.Errorf("Can't find Ue with Ipv4[%s]", req.UeIpv4)
		}
	} else if req.UeIpv6 != "" {
		policy = ue.SMPolicyFindByIdentifiersIpv6(req.UeIpv6, req.SliceInfo, req.Dnn)
		if policy == nil {
			err = fmt.Errorf("Can't find Ue with Ipv6 prefix[%s]", req.UeIpv6)
		}
	} else {
		err = fmt.Errorf("Ue finding by MAC address does not support")
	}
	return policy, err
}

// AMF Status Subscription Methods
func (context *AMFContext) NewAmfStatusSubscription(subscriptionID string, subscriptionData AMFStatusSubscriptionData) {
	context.AMFStatusSubsData.Store(subscriptionID, subscriptionData)
}

// UDR URI Methods
func (context *AMFContext) SetDefaultUdrURI(uri string) {
	context.DefaultUdrURILock.Lock()
	defer context.DefaultUdrURILock.Unlock()
	context.DefaultUdrURI = uri
}

// Utility Methods
func GetTimeformat() string {
	return GetSelf().TimeFormat
}

func GetUri(name models.ServiceName) string {
	return GetSelf().PcfServiceUris[name]
}

// 20241125 add for pc5
// Allocate PCF Ue with supi and add to pcf Context and returns allocated ue
func (c *AMFContext) NewPCFUe(Supi string) (*UeContext, error) {
	if strings.HasPrefix(Supi, "imsi-") {
		newUeContext := &UeContext{}
		newUeContext.SmPolicyData = make(map[string]*UeSmPolicyData)
		newUeContext.AMPolicyData = make(map[string]*UeAMPolicyData)
		newUeContext.PolAssociationIDGenerator = 1
		newUeContext.AppSessionIDGenerator = idgenerator.NewGenerator(1, math.MaxInt64)
		newUeContext.Supi = Supi
		c.UePool.Store(Supi, newUeContext)
		return newUeContext, nil
	} else {
		return nil, fmt.Errorf(" add Ue context fail ")
	}
}
