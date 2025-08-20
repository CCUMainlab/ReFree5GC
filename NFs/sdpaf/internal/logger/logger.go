package logger

import (
	"github.com/sirupsen/logrus"

	logger_util "github.com/free5gc/util/logger"
)

var (
	Log          *logrus.Logger
	NfLog        *logrus.Entry
	MainLog      *logrus.Entry
	InitLog      *logrus.Entry
	CfgLog       *logrus.Entry
	CtxLog       *logrus.Entry
	SBILog       *logrus.Entry
	GinLog       *logrus.Entry
	ConsumerLog  *logrus.Entry
	UeAuthLog    *logrus.Entry
	Auth5gAkaLog *logrus.Entry
	AuthELog     *logrus.Entry
	UtilLog      *logrus.Entry

	// 20250107 add logger for PCF
	SmPolicyLog   *logrus.Entry
	ProcLog       *logrus.Entry
	AmPolicyLog   *logrus.Entry
	CallbackLog   *logrus.Entry
	PolicyAuthLog *logrus.Entry
	BdtPolicyLog  *logrus.Entry
	OamLog        *logrus.Entry

	// 20250114 add logger from UDM
	EeLog  *logrus.Entry
	SdmLog *logrus.Entry
)

func init() {
	fieldsOrder := []string{
		logger_util.FieldNF,
		logger_util.FieldCategory,
	}

	Log = logger_util.New(fieldsOrder)
	NfLog = Log.WithField(logger_util.FieldNF, "SDPAF")
	MainLog = NfLog.WithField(logger_util.FieldCategory, "Main")
	InitLog = NfLog.WithField(logger_util.FieldCategory, "Init")
	CfgLog = NfLog.WithField(logger_util.FieldCategory, "CFG")
	CtxLog = NfLog.WithField(logger_util.FieldCategory, "CTX")
	SBILog = NfLog.WithField(logger_util.FieldCategory, "SBI")
	GinLog = NfLog.WithField(logger_util.FieldCategory, "GIN")
	ConsumerLog = NfLog.WithField(logger_util.FieldCategory, "Consumer")
	UeAuthLog = NfLog.WithField(logger_util.FieldCategory, "UeAuth")
	Auth5gAkaLog = NfLog.WithField(logger_util.FieldCategory, "5gAka")
	AuthELog = NfLog.WithField(logger_util.FieldCategory, "Eap")
	UtilLog = NfLog.WithField(logger_util.FieldCategory, "Util")

	// 20250107 add logger from PCF
	SmPolicyLog = NfLog.WithField(logger_util.FieldCategory, "SmPolicy")
	ProcLog = NfLog.WithField(logger_util.FieldCategory, "Proc")
	AmPolicyLog = NfLog.WithField(logger_util.FieldCategory, "AmPol")
	CallbackLog = NfLog.WithField(logger_util.FieldCategory, "Callback")
	PolicyAuthLog = NfLog.WithField(logger_util.FieldCategory, "PolAuth")
	BdtPolicyLog = NfLog.WithField(logger_util.FieldCategory, "BdtPol")

	// 20250114 add loger from UDM
	EeLog = NfLog.WithField(logger_util.FieldCategory, "EE")
	SdmLog = NfLog.WithField(logger_util.FieldCategory, "SDM")
}
