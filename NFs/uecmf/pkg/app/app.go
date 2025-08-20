package app

import (
	udm_context "github.com/free5gc/uecmf/internal/context"
	"github.com/free5gc/uecmf/pkg/factory"
)

type App interface {
	SetLogEnable(enable bool)
	SetLogLevel(level string)
	SetReportCaller(reportCaller bool)

	Start()
	Terminate()

	Context() *udm_context.UDMContext
	Config() *factory.Config
}
