package mobilebridge

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
)

type tunnelMetrics struct {
	up, down, active, dns atomic.Int64
	diagnostic            atomic.Value
}

var currentTunnelMetrics atomic.Pointer[tunnelMetrics]

func init() { resetTunnelDiagnostics() }
func resetTunnelDiagnostics() *tunnelMetrics {
	m := &tunnelMetrics{}
	m.diagnostic.Store("")
	currentTunnelMetrics.Store(m)
	return m
}
func (h *vpnFlowHandler) metricsOrCurrent() *tunnelMetrics {
	if h.metrics != nil {
		return h.metrics
	}
	return currentTunnelMetrics.Load()
}
func TunnelUploaded() int64    { return currentTunnelMetrics.Load().up.Load() }
func TunnelDownloaded() int64  { return currentTunnelMetrics.Load().down.Load() }
func TunnelConnections() int64 { return currentTunnelMetrics.Load().active.Load() }
func TunnelDNSQueries() int64  { return currentTunnelMetrics.Load().dns.Load() }
func TunnelLastError() string  { return currentTunnelMetrics.Load().diagnostic.Load().(string) }
func (h *vpnFlowHandler) recordError(stage string, err error) {
	if err == nil {
		return
	}
	reason := "节点或协议转发失败"
	var network net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &network) && network.Timeout()) {
		reason = "等待节点响应超时"
	} else if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		reason = "节点提前关闭连接"
	}
	// Do not expose credentials, query names, destinations or raw peer messages.
	h.metricsOrCurrent().diagnostic.Store(stage + "：" + reason)
}

type countedWriter struct {
	io.Writer
	counter *atomic.Int64
}

func (w countedWriter) Write(p []byte) (int, error) {
	n, e := w.Writer.Write(p)
	w.counter.Add(int64(n))
	return n, e
}
