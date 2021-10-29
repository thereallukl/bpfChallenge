package prometheus

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func ServePrometheus() {
	http.Handle("/metrics", promhttp.HandlerFor(prometheus.DefaultGatherer,
		promhttp.HandlerOpts{
			EnableOpenMetrics: false,
		}))
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request)  {
		fmt.Fprintf(w, "<html><body><a href=\"/metrics\">metrics</a></body></html>")
	})
	fmt.Errorf("failed to start prometheus endpoint: %s", http.ListenAndServe(":8080", nil))
}