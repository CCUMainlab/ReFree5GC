package consumer

import (
	"github.com/free5gc/openapi/Namf_Communication"
	"github.com/free5gc/openapi/Nnrf_NFDiscovery"
	"github.com/free5gc/openapi/Nnrf_NFManagement"
	"github.com/free5gc/openapi/Nudm_UEAuthentication"
	"github.com/free5gc/openapi/Nudr_DataRepository"
	"github.com/free5gc/sdpaf/pkg/app"
)

type ConsumerAusf interface {
	app.App
}

type Consumer struct {
	ConsumerAusf

	*nnrfService
	*nudmService
	*namfService
	*nudrService
}

func NewConsumer(ausf ConsumerAusf) (*Consumer, error) {
	c := &Consumer{
		ConsumerAusf: ausf,
	}

	c.nnrfService = &nnrfService{
		consumer:        c,
		nfMngmntClients: make(map[string]*Nnrf_NFManagement.APIClient),
		nfDiscClients:   make(map[string]*Nnrf_NFDiscovery.APIClient),
	}

	c.nudmService = &nudmService{
		consumer:    c,
		ueauClients: make(map[string]*Nudm_UEAuthentication.APIClient),
	}

	c.namfService = &namfService{
		consumer:     c,
		nfComClients: make(map[string]*Namf_Communication.APIClient),
	}

	c.nudrService = &nudrService{
		consumer:         c,
		nfDataSubClients: make(map[string]*Nudr_DataRepository.APIClient),
	}

	return c, nil
}
