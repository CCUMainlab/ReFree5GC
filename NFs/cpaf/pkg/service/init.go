package service

import (
	"context"
	"io"
	"os"
	"runtime/debug"
	"sync"

	"github.com/sirupsen/logrus"

	cpaf_context "github.com/free5gc/cpaf/internal/context"
	"github.com/free5gc/cpaf/internal/logger"
	"github.com/free5gc/cpaf/internal/ngap"
	ngap_message "github.com/free5gc/cpaf/internal/ngap/message"
	ngap_service "github.com/free5gc/cpaf/internal/ngap/service"
	"github.com/free5gc/cpaf/internal/sbi"
	"github.com/free5gc/cpaf/internal/sbi/consumer"
	"github.com/free5gc/cpaf/internal/sbi/processor"
	callback "github.com/free5gc/cpaf/internal/sbi/processor/notifier"
	"github.com/free5gc/cpaf/pkg/app"
	"github.com/free5gc/cpaf/pkg/factory"
	"github.com/free5gc/openapi/models"
)

type CpafAppInterface interface {
	app.App
	consumer.ConsumerAmf
	Consumer() *consumer.Consumer
	Processor() *processor.Processor
}

var CPAF CpafAppInterface

type CpafApp struct {
	CpafAppInterface

	cfg     *factory.Config
	cpafCtx *cpaf_context.AMFContext
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	processor *processor.Processor
	consumer  *consumer.Consumer
	sbiServer *sbi.Server
}

func NewApp(ctx context.Context, cfg *factory.Config, tlsKeyLogPath string) (*CpafApp, error) {
	cpaf := &CpafApp{
		cfg: cfg,
	}
	cpaf.SetLogEnable(cfg.GetLogEnable())
	cpaf.SetLogLevel(cfg.GetLogLevel())
	cpaf.SetReportCaller(cfg.GetLogReportCaller())

	consumer, err := consumer.NewConsumer(cpaf)
	if err != nil {
		return cpaf, err
	}
	cpaf.consumer = consumer

	processor, err_p := processor.NewProcessor(cpaf)
	if err_p != nil {
		return cpaf, err_p
	}
	cpaf.processor = processor

	cpaf.ctx, cpaf.cancel = context.WithCancel(ctx)
	cpaf.cpafCtx = cpaf_context.GetSelf()

	if cpaf.sbiServer, err = sbi.NewServer(cpaf, tlsKeyLogPath); err != nil {
		return nil, err
	}

	CPAF = cpaf

	return cpaf, nil
}

func (a *CpafApp) SetLogEnable(enable bool) {
	logger.MainLog.Infof("Log enable is set to [%v]", enable)
	if enable && logger.Log.Out == os.Stderr {
		return
	} else if !enable && logger.Log.Out == io.Discard {
		return
	}

	a.cfg.SetLogEnable(enable)
	if enable {
		logger.Log.SetOutput(os.Stderr)
	} else {
		logger.Log.SetOutput(io.Discard)
	}
}

func (a *CpafApp) SetLogLevel(level string) {
	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		logger.MainLog.Warnf("Log level [%s] is invalid", level)
		return
	}

	logger.MainLog.Infof("Log level is set to [%s]", level)
	if lvl == logger.Log.GetLevel() {
		return
	}

	a.cfg.SetLogLevel(level)
	logger.Log.SetLevel(lvl)
}

func (a *CpafApp) SetReportCaller(reportCaller bool) {
	logger.MainLog.Infof("Report Caller is set to [%v]", reportCaller)
	if reportCaller == logger.Log.ReportCaller {
		return
	}

	a.cfg.SetLogReportCaller(reportCaller)
	logger.Log.SetReportCaller(reportCaller)
}

func (a *CpafApp) Start() {
	self := a.Context()
	cpaf_context.InitAmfContext(self)

	ngapHandler := ngap_service.NGAPHandler{
		HandleMessage:         ngap.Dispatch,
		HandleNotification:    ngap.HandleSCTPNotification,
		HandleConnectionError: ngap.HandleSCTPConnError,
	}

	sctpConfig := ngap_service.NewSctpConfig(factory.AmfConfig.GetSctpConfig())
	ngap_service.Run(a.Context().NgapIpList, a.Context().NgapPort, ngapHandler, sctpConfig)
	logger.InitLog.Infoln("Server started")

	a.wg.Add(1)
	go a.listenShutdownEvent()

	if err := a.sbiServer.Run(context.Background(), &a.wg); err != nil {
		logger.MainLog.Fatalf("Run SBI server failed: %+v", err)
	}
	a.WaitRoutineStopped()
}

// Used in CPAF planned removal procedure
func (a *CpafApp) Terminate() {
	a.cancel()
}

func (a *CpafApp) Config() *factory.Config {
	return a.cfg
}

func (a *CpafApp) Context() *cpaf_context.AMFContext {
	return a.cpafCtx
}

func (a *CpafApp) CancelContext() context.Context {
	return a.ctx
}

func (a *CpafApp) Consumer() *consumer.Consumer {
	return a.consumer
}

func (a *CpafApp) Processor() *processor.Processor {
	return a.processor
}

func (a *CpafApp) listenShutdownEvent() {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.MainLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
		a.wg.Done()
	}()

	<-a.ctx.Done()
	a.terminateProcedure()
}

func (a *CpafApp) CallServerStop() {
	if a.sbiServer != nil {
		a.sbiServer.Stop()
	}
}

func (a *CpafApp) WaitRoutineStopped() {
	a.wg.Wait()
	logger.MainLog.Infof("CPAF App is terminated")
}

func (a *CpafApp) terminateProcedure() {
	logger.MainLog.Infof("Terminating CPAF...")
	a.CallServerStop()
	// deregister with NRF
	problemDetails, err_deg := a.Consumer().SendDeregisterNFInstance()
	if problemDetails != nil {
		logger.MainLog.Errorf("Deregister NF instance Failed Problem[%+v]", problemDetails)
	} else if err_deg != nil {
		logger.MainLog.Errorf("Deregister NF instance Error[%+v]", err_deg)
	} else {
		logger.MainLog.Infof("[CPAF] Deregister from NRF successfully")
	}

	// TODO: forward registered UE contexts to target CPAF in the same CPAF set if there is one

	// ngap
	// send CPAF status indication to ran to notify ran that this CPAF will be unavailable
	logger.MainLog.Infof("Send CPAF Status Indication to Notify RANs due to CPAF terminating")
	cpafSelf := a.Context()
	unavailableGuamiList := ngap_message.BuildUnavailableGUAMIList(cpafSelf.ServedGuamiList)
	cpafSelf.AmfRanPool.Range(func(key, value interface{}) bool {
		ran := value.(*cpaf_context.AmfRan)
		ngap_message.SendAMFStatusIndication(ran, unavailableGuamiList)
		return true
	})
	ngap_service.Stop()
	callback.SendAmfStatusChangeNotify((string)(models.StatusChange_UNAVAILABLE), cpafSelf.ServedGuamiList)
}
