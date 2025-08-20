package context

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"

	//"github.com/free5gc/openapi"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/sdpaf/internal/logger"
	"github.com/free5gc/sdpaf/pkg/factory"
)

func InitAusfContext(context *AUSFContext) {
	config := factory.AusfConfig
	logger.InitLog.Infof("sdpafconfig Info: Version[%s] Description[%s]\n", config.Info.Version, config.Info.Description)

	configuration := config.Configuration
	sbi := configuration.Sbi

	// add for pcf related
	if configuration.PcfName != "" {
		context.Name = configuration.PcfName
	}

	// 初始化 PCF 相关的 map
	context.PcfServiceUris = make(map[models.ServiceName]string)
	context.PcfSuppFeats = make(map[models.ServiceName]openapi.SupportedFeature)

	context.NfId = uuid.New().String()
	context.GroupID = configuration.GroupId
	context.NrfUri = configuration.NrfUri
	context.NrfCertPem = configuration.NrfCertPem
	context.UriScheme = models.UriScheme(configuration.Sbi.Scheme) // default uri scheme
	context.RegisterIPv4 = factory.AusfSbiDefaultIPv4              // default localhost
	context.SBIPort = factory.AusfSbiDefaultPort                   // default port
	if sbi != nil {
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
			logger.InitLog.Info("Parsing ServerIPv4 address from ENV Variable.")
		} else {
			context.BindingIPv4 = sbi.BindingIPv4
			if context.BindingIPv4 == "" {
				logger.InitLog.Warn("Error parsing ServerIPv4 address as string. Using the 0.0.0.0 address as default.")
				context.BindingIPv4 = "0.0.0.0"
			}
		}
	}

	context.Url = string(context.UriScheme) + "://" + context.RegisterIPv4 + ":" + strconv.Itoa(context.SBIPort)
	context.PlmnList = append(context.PlmnList, configuration.PlmnSupportList...)

	// context.NfService
	context.NfService = make(map[models.ServiceName]models.NfService)
	AddNfServices(&context.NfService, config, context)
	fmt.Println("ausf context = ", context)

	context.EapAkaSupiImsiPrefix = configuration.EapAkaSupiImsiPrefix
	context.TimeFormat = configuration.TimeFormat
	context.DefaultBdtRefId = configuration.DefaultBdtRefId

	// 设置服务 URI 和特性支持
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

// func AddNfServices(serviceMap *map[models.ServiceName]models.NfService, config *factory.Config, context *AUSFContext) {
// 	var nfService models.NfService
// 	var ipEndPoints []models.IpEndPoint
// 	var nfServiceVersions []models.NfServiceVersion
// 	services := *serviceMap

// 	// nausf-auth
// 	nfService.ServiceInstanceId = context.NfId
// 	nfService.ServiceName = models.ServiceName_NAUSF_AUTH

// 	var ipEndPoint models.IpEndPoint
// 	ipEndPoint.Ipv4Address = context.RegisterIPv4
// 	ipEndPoint.Port = int32(context.SBIPort)
// 	ipEndPoints = append(ipEndPoints, ipEndPoint)

// 	var nfServiceVersion models.NfServiceVersion
// 	nfServiceVersion.ApiFullVersion = config.Info.Version
// 	nfServiceVersion.ApiVersionInUri = "v1"
// 	nfServiceVersions = append(nfServiceVersions, nfServiceVersion)

// 	nfService.Scheme = context.UriScheme
// 	nfService.NfServiceStatus = models.NfServiceStatus_REGISTERED

// 	nfService.IpEndPoints = &ipEndPoints
// 	nfService.Versions = &nfServiceVersions
// 	services[models.ServiceName_NAUSF_AUTH] = nfService
// }

func AddNfServices(serviceMap *map[models.ServiceName]models.NfService, config *factory.Config, context *AUSFContext) {
	services := *serviceMap

	// nausf-auth (原有的AUSF服務)
	var nausfService models.NfService
	nausfService.ServiceInstanceId = context.NfId + "-auth"
	nausfService.ServiceName = models.ServiceName_NAUSF_AUTH
	nausfService.Scheme = context.UriScheme
	nausfService.NfServiceStatus = models.NfServiceStatus_REGISTERED

	var nausfIpEndPoints []models.IpEndPoint
	var nausfIpEndPoint models.IpEndPoint
	nausfIpEndPoint.Ipv4Address = context.RegisterIPv4
	nausfIpEndPoint.Port = int32(context.SBIPort)
	nausfIpEndPoints = append(nausfIpEndPoints, nausfIpEndPoint)
	nausfService.IpEndPoints = &nausfIpEndPoints

	var nausfVersions []models.NfServiceVersion
	var nausfVersion models.NfServiceVersion
	nausfVersion.ApiFullVersion = config.Info.Version
	nausfVersion.ApiVersionInUri = "v1"
	nausfVersions = append(nausfVersions, nausfVersion)
	nausfService.Versions = &nausfVersions

	services[models.ServiceName_NAUSF_AUTH] = nausfService

	// 添加 npcf-smpolicycontrol 服務
	var pcfService models.NfService
	pcfService.ServiceInstanceId = context.NfId + "-smpolicycontrol"
	pcfService.ServiceName = models.ServiceName_NPCF_SMPOLICYCONTROL
	pcfService.Scheme = context.UriScheme
	pcfService.NfServiceStatus = models.NfServiceStatus_REGISTERED

	var pcfIpEndPoints []models.IpEndPoint
	var pcfIpEndPoint models.IpEndPoint
	pcfIpEndPoint.Ipv4Address = context.RegisterIPv4
	pcfIpEndPoint.Port = int32(context.SBIPort)
	pcfIpEndPoints = append(pcfIpEndPoints, pcfIpEndPoint)
	pcfService.IpEndPoints = &pcfIpEndPoints

	var pcfVersions []models.NfServiceVersion
	var pcfVersion models.NfServiceVersion
	pcfVersion.ApiFullVersion = config.Info.Version
	pcfVersion.ApiVersionInUri = "v1"
	pcfVersions = append(pcfVersions, pcfVersion)
	pcfService.Versions = &pcfVersions

	services[models.ServiceName_NPCF_SMPOLICYCONTROL] = pcfService

	// 添加 npcf-policyauthorization 服務
	var policyAuthService models.NfService
	policyAuthService.ServiceInstanceId = context.NfId + "-policyauthorization"
	policyAuthService.ServiceName = models.ServiceName_NPCF_POLICYAUTHORIZATION
	policyAuthService.Scheme = context.UriScheme
	policyAuthService.NfServiceStatus = models.NfServiceStatus_REGISTERED

	var policyAuthIpEndPoints []models.IpEndPoint
	var policyAuthIpEndPoint models.IpEndPoint
	policyAuthIpEndPoint.Ipv4Address = context.RegisterIPv4
	policyAuthIpEndPoint.Port = int32(context.SBIPort)
	policyAuthIpEndPoints = append(policyAuthIpEndPoints, policyAuthIpEndPoint)
	policyAuthService.IpEndPoints = &policyAuthIpEndPoints

	var policyAuthVersions []models.NfServiceVersion
	var policyAuthVersion models.NfServiceVersion
	policyAuthVersion.ApiFullVersion = config.Info.Version
	policyAuthVersion.ApiVersionInUri = "v1"
	policyAuthVersions = append(policyAuthVersions, policyAuthVersion)
	policyAuthService.Versions = &policyAuthVersions

	services[models.ServiceName_NPCF_POLICYAUTHORIZATION] = policyAuthService
}

// Init NfService with supported service list ,and version of services
func (c *AUSFContext) InitNFService(serviceList []factory.Service, version string) {
	tmpVersion := strings.Split(version, ".")
	versionUri := "v" + tmpVersion[0]
	for index, service := range serviceList {
		name := models.ServiceName(service.ServiceName)
		c.NfService[name] = models.NfService{
			ServiceInstanceId: strconv.Itoa(index),
			ServiceName:       name,
			Versions: &[]models.NfServiceVersion{
				{
					ApiFullVersion:  version,
					ApiVersionInUri: versionUri,
				},
			},
			Scheme:          c.UriScheme,
			NfServiceStatus: models.NfServiceStatus_REGISTERED,
			ApiPrefix:       c.GetIPv4Uri(),
			IpEndPoints: &[]models.IpEndPoint{
				{
					Ipv4Address: c.RegisterIPv4,
					Transport:   models.TransportProtocol_TCP,
					Port:        int32(c.SBIPort),
				},
			},
			SupportedFeatures: service.SuppFeat,
		}
	}
}
