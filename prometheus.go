package main

import (
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	syscallSuccess = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "syscall_success_total",
			Help: "Total number of successful system calls",
		},
		[]string{"syscall"},
	)

	syscallFailure = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "syscall_failure_total",
			Help: "Total number of failed system calls",
		},
		[]string{"syscall"},
	)

	contextSwitchCounts = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "context_switch_counts_total",
			Help: "Total number of context switches",
		},
		[]string{"context_switch"},
	)
)

func init() {
	prometheus.MustRegister(syscallSuccess)
	prometheus.MustRegister(syscallFailure)
	prometheus.MustRegister(contextSwitchCounts)
}

func startPrometheusServer() {
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		if err := http.ListenAndServe(":2112", nil); err != nil {
			log.Fatalf("failed to start HTTP server: %v", err)
		}
	}()
}

func updatePrometheusMetrics(syscallName string, successCount, failureCount uint64) {
	syscallSuccess.WithLabelValues(syscallName).Set(float64(successCount))
	syscallFailure.WithLabelValues(syscallName).Set(float64(failureCount))
}

func updatePrometheusContextSwitchMetrics(count uint64) {
	contextSwitchCounts.WithLabelValues("total").Set(float64(count))
}
