// SPDX-License-Identifier: MPL-2.0
// NOWAY per-source counters alongside upstream authenticated-user counters.
package dispatcher

import (
    "context"
    "net/netip"
    "sync"

    "github.com/xtls/xray-core/common/buf"
    "github.com/xtls/xray-core/common/session"
    "github.com/xtls/xray-core/features/stats"
    "github.com/xtls/xray-core/transport"
)

var nowayCounters = struct { sync.Mutex; count int }{}

func nowayIPCounter(ctx context.Context, sm stats.Manager, email, direction string) stats.Counter {
    inbound := session.InboundFromContext(ctx)
    if inbound == nil || inbound.Source.Address == nil { return nil }
    address, err := netip.ParseAddr(inbound.Source.Address.String())
    if err != nil { return nil }
    name := "user>>>" + email + ">>>ip>>>" + address.Unmap().String() + ">>>traffic>>>" + direction
    if existing := sm.GetCounter(name); existing != nil { return existing }
    nowayCounters.Lock()
    defer nowayCounters.Unlock()
    if existing := sm.GetCounter(name); existing != nil { return existing }
    // Bound authenticated IP churn. Preserve account totals and explicitly
    // signal incomplete IP attribution instead of inventing a distribution.
    if nowayCounters.count >= 32768 {
        if c, _ := sm.GetOrRegisterCounter("user>>>noway-meter>>>overflow"); c != nil { c.Add(1) }
        return nil
    }
    counter, _ := sm.GetOrRegisterCounter(name)
    if counter != nil { nowayCounters.count++ }
    return counter
}

type nowayPair struct { account, ip stats.Counter }
func (p *nowayPair) Value() int64 { return p.account.Value() }
func (p *nowayPair) Set(v int64) int64 { p.ip.Set(v); return p.account.Set(v) }
func (p *nowayPair) Add(v int64) int64 { p.ip.Add(v); return p.account.Add(v) }

func nowayMeterLinks(ctx context.Context, sm stats.Manager, email string, in, out *transport.Link) {
    if c := nowayIPCounter(ctx, sm, email, "uplink"); c != nil {
        in.Writer = &SizeStatWriter{Counter: c, Writer: in.Writer}
    }
    if c := nowayIPCounter(ctx, sm, email, "downlink"); c != nil {
        out.Writer = &SizeStatWriter{Counter: c, Writer: out.Writer}
    }
}

func nowayMeterWrapped(ctx context.Context, sm stats.Manager, email string, link *transport.Link) {
    if c := nowayIPCounter(ctx, sm, email, "uplink"); c != nil {
        reader := link.Reader.(*buf.TimeoutWrapperReader)
        if reader.Counter == nil { reader.Counter = c } else { reader.Counter = &nowayPair{reader.Counter, c} }
    }
    if c := nowayIPCounter(ctx, sm, email, "downlink"); c != nil {
        link.Writer = &SizeStatWriter{Counter: c, Writer: link.Writer}
    }
}
