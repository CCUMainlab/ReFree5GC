package app

import (
	pcf_context "github.com/free5gc/apcf/internal/context"
	"github.com/free5gc/apcf/pkg/factory"
)

type App interface {
	SetLogEnable(enable bool)
	SetLogLevel(level string)
	SetReportCaller(reportCaller bool)

	Start()
	Terminate()

	Context() *pcf_context.PCFContext
	Config() *factory.Config
}
