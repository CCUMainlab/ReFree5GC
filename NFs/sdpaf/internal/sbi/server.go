package sbi

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/free5gc/openapi/models"
	ausf_context "github.com/free5gc/sdpaf/internal/context"
	"github.com/free5gc/sdpaf/internal/logger"
	"github.com/free5gc/sdpaf/internal/sbi/consumer"
	"github.com/free5gc/sdpaf/internal/sbi/processor"
	"github.com/free5gc/sdpaf/internal/util"
	"github.com/free5gc/sdpaf/pkg/app"
	"github.com/free5gc/sdpaf/pkg/factory"
	"github.com/free5gc/util/httpwrapper"
	logger_util "github.com/free5gc/util/logger"
)

type ServerAusf interface {
	app.App

	Consumer() *consumer.Consumer
	Processor() *processor.Processor
}

type Server struct {
	ServerAusf

	httpServer *http.Server
	router     *gin.Engine
}

func NewServer(ausf ServerAusf, tlsKeyLogPath string) (*Server, error) {
	s := &Server{
		ServerAusf: ausf,
	}

	s.router = newRouter(s)

	cfg := s.Config()
	bindAddr := cfg.GetSbiBindingAddr()
	logger.SBILog.Infof("Binding addr: [%s]", bindAddr)
	var err error
	if s.httpServer, err = httpwrapper.NewHttp2Server(bindAddr, tlsKeyLogPath, s.router); err != nil {
		logger.InitLog.Errorf("Initialize HTTP server failed: %v", err)
		return nil, err
	}
	s.httpServer.ErrorLog = log.New(logger.SBILog.WriterLevel(logrus.ErrorLevel), "HTTP2: ", 0)

	return s, nil
}

func newRouter(s *Server) *gin.Engine {
	router := logger_util.NewGinWithLogrus(logger.GinLog)

	// for debug
	if factory.AusfConfig == nil || factory.AusfConfig.Configuration == nil {
		logger.InitLog.Fatal("AusfConfig or Configuration is not initialized")
		return router
	}

	// 確保 ServiceNameList 存在且不為空
	if len(factory.AusfConfig.Configuration.ServiceNameList) == 0 {
		logger.InitLog.Warn("ServiceNameList is empty")
		return router
	}

	for _, serverName := range factory.AusfConfig.Configuration.ServiceNameList {
		switch models.ServiceName(serverName) {
		case models.ServiceName_NAUSF_AUTH:
			ausfUeAuthenticationGroup := router.Group(factory.AusfAuthResUriPrefix)
			ausfUeAuthenticationRoutes := s.getUeAuthenticationRoutes()
			routerAuthorizationCheck := util.NewRouterAuthorizationCheck(models.ServiceName_NAUSF_AUTH)
			ausfUeAuthenticationGroup.Use(func(c *gin.Context) {
				routerAuthorizationCheck.Check(c, ausf_context.GetSelf())
			})
			applyRoutes(ausfUeAuthenticationGroup, ausfUeAuthenticationRoutes)
		case models.ServiceName_NAUSF_SORPROTECTION:
			ausfSorprotectionGroup := router.Group(factory.AusfSorprotectionResUriPrefix)
			ausfSorprotectionRoutes := s.getSorprotectionRoutes()
			routerAuthorizationCheck := util.NewRouterAuthorizationCheck(models.ServiceName_NAUSF_SORPROTECTION)
			ausfSorprotectionGroup.Use(func(c *gin.Context) {
				routerAuthorizationCheck.Check(c, ausf_context.GetSelf())
			})
			applyRoutes(ausfSorprotectionGroup, ausfSorprotectionRoutes)
		case models.ServiceName_NAUSF_UPUPROTECTION:
			ausfUpuprotectionGroup := router.Group(factory.AusfUpuprotectionResUriPrefix)
			ausfUpuprotectionRoutes := s.getUpuprotectionRoutes()
			routerAuthorizationCheck := util.NewRouterAuthorizationCheck(models.ServiceName_NAUSF_UPUPROTECTION)
			ausfUpuprotectionGroup.Use(func(c *gin.Context) {
				routerAuthorizationCheck.Check(c, ausf_context.GetSelf())
			})
			applyRoutes(ausfUpuprotectionGroup, ausfUpuprotectionRoutes)
		// 20250107 add for PCF
		case models.ServiceName_NPCF_SMPOLICYCONTROL:
			smPolicyGroup := router.Group(factory.PcfSMpolicyCtlResUriPrefix)
			smPolicyRoutes := s.getSmPolicyRoutes()
			// routerAuthorizationCheck := util.NewRouterAuthorizationCheck(models.ServiceName_NPCF_SMPOLICYCONTROL)
			// smPolicyGroup.Use(func(c *gin.Context) {
			// 	routerAuthorizationCheck.Check(c, ausf_context.GetSelf())
			// })
			applyRoutes(smPolicyGroup, smPolicyRoutes)
		case models.ServiceName_NPCF_POLICYAUTHORIZATION:
			policyAuthorizationGroup := router.Group(factory.PcfPolicyAuthResUriPrefix)
			policyAuthorizationRoutes := s.getPolicyAuthorizationRoutes()
			// policyAuthorizationRouterAuthorizationCheck := util.
			// 	NewRouterAuthorizationCheck(models.ServiceName_NPCF_POLICYAUTHORIZATION)
			// policyAuthorizationGroup.Use(func(c *gin.Context) {
			// 	policyAuthorizationRouterAuthorizationCheck.Check(c, s.Context())
			// })
			applyRoutes(policyAuthorizationGroup, policyAuthorizationRoutes)
		// 20250114 add for UDM
		case models.ServiceName_NUDM_EE:
			udmEEGroup := s.router.Group(factory.UdmEeResUriPrefix)
			udmEERoutes := s.getEventExposureRoutes()
			routerAuthorizationCheck := util.NewRouterAuthorizationCheck(models.ServiceName_NUDM_EE)
			udmEEGroup.Use(func(c *gin.Context) {
				routerAuthorizationCheck.Check(c, s.Context())
			})
			applyRoutes(udmEEGroup, udmEERoutes)
		case models.ServiceName_NUDM_SDM:
			udmSDMGroup := router.Group(factory.UdmSdmResUriPrefix)
			udmSDMRoutes := s.getSubscriberDataManagementRoutes()
			routerAuthorizationCheck := util.NewRouterAuthorizationCheck(models.ServiceName_NUDM_SDM)
			udmSDMGroup.Use(func(c *gin.Context) {
				routerAuthorizationCheck.Check(c, ausf_context.GetSelf())
			})
			applyRoutes(udmSDMGroup, udmSDMRoutes)

			oneLayerPath := "/:supi"
			udmSDMGroup.Any(oneLayerPath, s.OneLayerPathHandlerFunc)

			twoLayerPath := "/:supi/:subscriptionId"
			udmSDMGroup.Any(twoLayerPath, s.TwoLayerPathHandlerFunc)

			threeLayerPath := "/:supi/:subscriptionId/:thirdLayer"
			udmSDMGroup.Any(threeLayerPath, s.ThreeLayerPathHandlerFunc)
		}
	}

	return router
}

func (s *Server) Run(traceCtx context.Context, wg *sync.WaitGroup) error {
	var err error
	_, s.Context().NfId, err = s.Consumer().RegisterNFInstance(context.Background())
	if err != nil {
		logger.InitLog.Errorf("AUSF register to NRF Error[%s]", err.Error())
	}

	wg.Add(1)
	go s.startServer(wg)

	return nil
}

func (s *Server) Shutdown() {
	s.shutdownHttpServer()
}

func (s *Server) shutdownHttpServer() {
	const defaultShutdownTimeout time.Duration = 2 * time.Second

	if s.httpServer != nil {
		logger.SBILog.Infof("Stop SBI server (listen on %s)", s.httpServer.Addr)
		toCtx, cancel := context.WithTimeout(context.Background(), defaultShutdownTimeout)
		defer cancel()
		if err := s.httpServer.Shutdown(toCtx); err != nil {
			logger.SBILog.Errorf("Could not close SBI server: %#v", err)
		}
	}
}

func (s *Server) startServer(wg *sync.WaitGroup) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.SBILog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
			s.Terminate()
		}
		wg.Done()
	}()

	logger.SBILog.Infof("Start SBI server (listen on %s)", s.httpServer.Addr)

	var err error
	cfg := s.Config()
	scheme := cfg.GetSbiScheme()
	if scheme == "http" {
		err = s.httpServer.ListenAndServe()
	} else if scheme == "https" {
		err = s.httpServer.ListenAndServeTLS(
			cfg.GetCertPemPath(),
			cfg.GetCertKeyPath())
	} else {
		err = fmt.Errorf("no support this scheme[%s]", scheme)
	}

	if err != nil && err != http.ErrServerClosed {
		logger.SBILog.Errorf("SBI server error: %v", err)
	}
	logger.SBILog.Infof("SBI server (listen on %s) stopped", s.httpServer.Addr)
}
