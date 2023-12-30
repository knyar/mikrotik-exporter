package collector

import (
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/routeros.v2/proto"
)

type firewallCollector struct {
	props        []string
	descriptions map[string]*prometheus.Desc
}

func newFirewallCollector() routerOSCollector {
	c := &firewallCollector{}
	c.init()
	return c
}

func (c *firewallCollector) init() {
	c.props = []string{"chain", "action", "disabled", "comment", "bytes", "packets"}
	labelNames := []string{"name", "address", "chain", "action", "disabled", "comment"}
	c.descriptions = make(map[string]*prometheus.Desc)
	for _, p := range c.props[4:] {
		c.descriptions[p] = descriptionForPropertyName("firewall_rule", p, labelNames)
	}
}

func (c *firewallCollector) describe(ch chan<- *prometheus.Desc) {
	for _, d := range c.descriptions {
		ch <- d
	}
}

func (c *firewallCollector) collect(ctx *collectorContext) error {
	stats, err := c.fetch(ctx)
	if err != nil {
		return err
	}

	seen := make(map[string]bool)
	for _, re := range stats {
		comment := re.Map["comment"]

		// To avoid trying to export multiple metrics with the same labels,
		// only export counters for rules that have non-empty comments, and only
		// one metric for each unique comment value.
		if comment == "" || seen[comment] {
			continue
		}
		c.collectForStat(re, ctx)
		seen[comment] = true
	}

	return nil
}

func (c *firewallCollector) fetch(ctx *collectorContext) ([]*proto.Sentence, error) {
	reply, err := ctx.client.Run("/ip/firewall/filter/print", "=.proplist="+strings.Join(c.props, ","))
	if err != nil {
		log.WithFields(log.Fields{
			"device": ctx.device.Name,
			"error":  err,
		}).Error("error fetching firewall metrics")
		return nil, err
	}

	return reply.Re, nil
}

func (c *firewallCollector) collectForStat(re *proto.Sentence, ctx *collectorContext) {
	for _, p := range c.props[4:] {
		c.collectMetricForProperty(p, re, ctx)
	}
}

func (c *firewallCollector) collectMetricForProperty(property string, re *proto.Sentence, ctx *collectorContext) {
	desc := c.descriptions[property]
	if value := re.Map[property]; value != "" {
		vtype := prometheus.CounterValue
		v, err := strconv.ParseFloat(value, 64)
		if err != nil {
			log.WithFields(log.Fields{
				"device":   ctx.device.Name,
				"property": property,
				"value":    value,
				"error":    err,
			}).Error("error parsing firewall metric value")
			return
		}
		m, err := prometheus.NewConstMetric(desc, vtype, v, ctx.device.Name, ctx.device.Address,
			re.Map["chain"], re.Map["action"], re.Map["disabled"], re.Map["comment"])
		if err != nil {
			log.Error(err)
			return
		}
		ctx.ch <- m
	}
}
