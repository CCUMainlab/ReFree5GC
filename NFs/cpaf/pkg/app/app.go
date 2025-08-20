package app

import (
	amf_context "github.com/free5gc/cpaf/internal/context"
	"github.com/free5gc/cpaf/pkg/factory"
)

type App interface {
	SetLogEnable(enable bool)
	SetLogLevel(level string)
	SetReportCaller(reportCaller bool)

	Start()
	Terminate()

	Context() *amf_context.AMFContext
	Config() *factory.Config
}
