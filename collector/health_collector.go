package collector

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/routeros.v2/proto"
)

type healthCollector struct {
	props        []string
	descriptions map[string]*prometheus.Desc
}

func newhealthCollector() routerOSCollector {
	c := &healthCollector{}
	c.init()
	return c
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func (c *healthCollector) init() {
	c.props = []string{
		"voltage",
		"temperature",
		"cpu-temperature",
		"sfp-temperature",
		"board-temperature1",
		"board-temperature2",
		"fan1-speed",
		"fan2-speed",
		"fan3-speed",
	}

	labelNames := []string{"name", "address"}
	helpText := []string{
		"Input voltage to the RouterOS board, in volts",
		"Temperature of RouterOS board, in degrees Celsius",
		"Temperature of RouterOS CPU, in degrees Celsius",
		"Temperature of RouterOS SFP module, in degrees Celsius",
		"Temperature of RouterOS board - sensor 1, in degrees Celsius",
		"Temperature of RouterOS board - sensor 2, in degrees Celsius",
		"Fan 1 speed, in RPM",
		"Fan 2 speed, in RPM",
		"Fan 3 speed, in RPM",
	}
	c.descriptions = make(map[string]*prometheus.Desc)
	for i, p := range c.props {
		c.descriptions[p] = descriptionForPropertyNameHelpText("health", p, labelNames, helpText[i])
	}
}

func (c *healthCollector) describe(ch chan<- *prometheus.Desc) {
	for _, d := range c.descriptions {
		ch <- d
	}
}

func (c *healthCollector) collect(ctx *collectorContext) error {
	stats, err := c.fetch(ctx)
	if err != nil {
		return err
	}

	for _, re := range stats {
		c.collectForStat(re, ctx)
	}

	return nil
}

func (c *healthCollector) fetch(ctx *collectorContext) ([]*proto.Sentence, error) {
	reply, err := ctx.client.Run("/system/health/print", "=.proplist=name,value")
	if err != nil {
		log.WithFields(log.Fields{
			"device": ctx.device.Name,
			"error":  err,
		}).Error("error fetching system health metrics")
		return nil, err
	}

	return reply.Re, nil
}

func (c *healthCollector) collectForStat(re *proto.Sentence, ctx *collectorContext) {
	var v float64
	var err error

	if !contains(c.props, re.Map["name"]) {
		return
	}
	if re.Map["value"] == "" {
		return
	}
	v, err = strconv.ParseFloat(re.Map["value"], 64)

	if err != nil {
		log.WithFields(log.Fields{
			"device":   ctx.device.Name,
			"property": re.Map["name"],
			"value":    re.Map["value"],
			"error":    err,
		}).Error("error parsing system health metric value")
		return
	}

	desc := c.descriptions[re.Map["name"]]
	ctx.ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, v, ctx.device.Name, ctx.device.Address)
}
