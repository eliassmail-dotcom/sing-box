package group

// lx:begin SPEC 054 penalty failover (least_test)
//
// Реакция least_test-группы на отказы боевых дайлов. До этого группа не
// реагировала на ошибки вообще: выбор оставался прибит к мёртвому узлу до
// хвоста следующего пробного прогона (до interval, по умолчанию 3 мин), и с
// SPEC 052 пользователь получал ошибку за 15с — но группа её не потребляла.
//
// Механика (дизайн владельца, 2026-08-07):
//   - Отказ класса «путь мёртв» (isPathDeadDialError) даёт узлу +1 штраф и
//     ОДИН fallback-дайл через следующего кандидата (кап 2 попытки на дайл).
//     Успех fallback'а переносит на него выбор группы — без Interrupt.
//   - Штраф сбрасывается ТОЛЬКО доказательством жизни: успешный боевой дайл
//     или ответ на пробу в ретесте. Никаких сбросов по времени.
//   - Аварийный режим: у лучшего-по-скорости ≥ penaltyThreshold штрафов →
//     выбор ранжируется двумя уровнями (штрафы ↑, затем задержка ↑) среди
//     узлов с history. Обычно победителей по штрафам несколько — они
//     соревнуются по скорости, как обычный least_test.
//   - Тотальные штрафы (нет кандидата со штрафом < порога) → принудительный
//     force-прогон проб, не чаще раза в penaltyForcedRetestGap, отсчёт от
//     ЗАВЕРШЕНИЯ прошлого прогона (последнего ответа), не от старта.
//   - Режим failover (SPEC 116) пользуется той же машинерией: отказ
//     удерживаемого узла переносит выбор на лучшего кандидата через
//     penaltyFailoverDial, аварийный режим и клапан действуют как здесь.
//
// Отказ в подключении (ECONNREFUSED) и сброс при открытии (ECONNRESET) зависят
// от узла: у прокси-узла ошибка открытия возникает между нами и его сервером
// (процесс сервера остановлен, порт закрыт) — это «путь мёртв». Узел, который
// сам ходит до назначения при открытии (лист direct или endpoint,
// penaltySiteOnOpen), получает этот отказ от сайта — через другой узел будет
// тот же отказ, штрафа и fallback'а нет. Canceled — клиент ушёл сам. Причинная неоднозначность ошибок (мёртвый узел
// vs мёртвый сайт) принята: один заблокированный сайт может уронить группу в
// аварийный режим, но режим деградирует мягко (выбор уходит на здоровые узлы,
// всё продолжает работать) и смывается первым же ответившим ретестом.
// UDP штрафов не генерирует (у ListenPacket нет connect-сигнала), но выбором
// пользуется общим.
//
// round_robin (balancer != nil) does not use this machinery: its pool has its own
// health-check (SPEC 019 v2), and a failed open — a TCP dial, a UDP open
// (ListenPacket, a connected UDP flow) — goes to the SPEC 138 self-heal
// (urltest_rr_heal_lx.go): one retry through the next live slot and a background
// verdict on the node, which may drop the node's history and replace it in its
// slot. The open error by itself still changes neither history nor the pool.

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/lxtrace"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	// penaltyThreshold — штрафы лучшего-по-скорости, включающие аварийный режим.
	// С капом 2 (основной + fallback) это ~3 неудачных пользовательских попытки.
	penaltyThreshold = 3
	// penaltyForcedRetestGap — минимальная пауза между принудительными
	// force-прогонами при тотальных штрафах, от конца прошлого прогона.
	penaltyForcedRetestGap = 2 * time.Minute
)

// isPathDeadDialError отделяет «путь мёртв» (штраф и fallback) от «назначение
// отказало» (не штраф) и «клиент ушёл» (Canceled). Путь мёртв при таймауте и
// недостижимости; context.DeadlineExceeded — это в том числе 15s-дедлайн
// SPEC 052. Отказ в подключении и сброс при открытии — путь мёртв, если узел не
// ходит до назначения сам (siteOnOpen == false): тогда отказал сервер узла.
func isPathDeadDialError(err error, siteOnOpen bool) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	// lx C5 (b50 Windows): the plain syscall errno checks never match the real
	// Winsock codes (WSAEHOSTUNREACH 10065, WSAENETUNREACH 10051, WSAETIMEDOUT
	// 10060, WSAECONNREFUSED 10061, WSAECONNRESET 10054). Reuse the RR errno
	// tables of this package (urltest_rr_errors_lx.go), which already classify
	// both the Unix errnos and the Winsock codes (and gVisor texts), instead of
	// duplicating the mapping. Unix behaviour is unchanged: every errno of the
	// former checks is contained in the rr tables.
	if rrSilence(err) || errors.Is(err, syscall.ETIMEDOUT) || rrLocalError(err) {
		return true
	}
	if rrActiveRefusal(err) {
		return !siteOnOpen
	}
	// net.Error timeouts are already classified by rrSilence (peer review #5,
	// b50 Windows): it walks the same errors.As before the text fallback.
	return false
}

// penaltySiteOnOpen reports whether the leaf of node goes to the destination
// itself when a connection opens (siteOnOpenLx): its refused or reset dial is the
// site's answer.
func penaltySiteOnOpen(ctx context.Context, outbounds adapter.OutboundManager, node adapter.Outbound) bool {
	return siteOnOpenLx(ctx, outbounds, node)
}

// pathDead classifies a failed dial through node (isPathDeadDialError).
func (g *URLTestGroup) pathDead(node adapter.Outbound, err error) bool {
	return isPathDeadDialError(err, penaltySiteOnOpen(g.ctx, g.outbound, node))
}

func (g *URLTestGroup) penaltyOf(tag string) int64 {
	value, ok := g.penalties.Load(tag)
	if !ok {
		return 0
	}
	return value.(*atomic.Int64).Load()
}

func (g *URLTestGroup) penaltyAdd(tag string) {
	value, _ := g.penalties.LoadOrStore(tag, new(atomic.Int64))
	value.(*atomic.Int64).Add(1)
}

// penaltyReset — единственный путь обнуления: доказательство жизни (успешный
// боевой дайл или ответ на пробу).
func (g *URLTestGroup) penaltyReset(tag string) {
	if value, ok := g.penalties.Load(tag); ok {
		value.(*atomic.Int64).Store(0)
	}
}

// fastestByDelay — узел с минимальной задержкой среди имеющих history: чистая
// «скорость», без tolerance-гистерезиса и без привязки к текущему выбору.
func (g *URLTestGroup) fastestByDelay(network string) adapter.Outbound {
	// In a Smart priority group, evaluate the preferred tier first. A very fast
	// White node must not hide repeated failures of the fastest still-healthy Base.
	if len(g.priorityOutbounds) > 0 {
		for _, tier := range []int{0, 1, 2} {
			if best := g.fastestByDelayTier(network, tier); best != nil {
				return best
			}
		}
		return nil
	}
	return g.fastestByDelayTier(network, 2)
}

func (g *URLTestGroup) fastestByDelayTier(network string, preferred int) adapter.Outbound {
	var minDelay uint16
	var minOutbound adapter.Outbound
	for _, detour := range g.outbounds {
		if len(g.priorityOutbounds) > 0 && g.priorityTier(detour.Tag()) != preferred {
			continue
		}
		if !supportsNetwork(detour, network) || !g.guardAllows(RealTag(detour, network)) {
			continue
		}
		history := g.history.LoadURLTestHistory(RealTag(detour, network))
		if history == nil {
			continue
		}
		if minOutbound == nil || history.Delay < minDelay {
			minDelay = history.Delay
			minOutbound = detour
		}
	}
	return minOutbound
}

// penaltyEmergency — аварийный режим: лучший-по-скорости набрал ≥ порога.
func (g *URLTestGroup) penaltyEmergency(network string) bool {
	fastest := g.fastestByDelay(network)
	return fastest != nil && g.penaltyOf(RealTag(fastest, N.NetworkTCP)) >= penaltyThreshold
}

// penaltyBest — двухуровневое ранжирование (штрафы ↑, задержка ↑) среди узлов
// с history, минус исключённый тег. nil, если кандидатов нет.
func (g *URLTestGroup) penaltyBest(network string, excludeTag string) adapter.Outbound {
	if len(g.priorityOutbounds) > 0 {
		// A successful fallback dial may not bypass another responsive primary.
		for _, preferred := range []int{0, 1, 2} {
			var choice adapter.Outbound
			var minPenalty int64
			var minDelay uint16
			for _, detour := range g.outbounds {
				if g.priorityTier(detour.Tag()) != preferred || !supportsNetwork(detour, network) || !g.guardAllows(RealTag(detour, N.NetworkTCP)) {
					continue
				}
				tag := RealTag(detour, N.NetworkTCP)
				if tag == excludeTag || !g.guardAllows(tag) {
					continue
				}
				history := g.history.LoadURLTestHistory(tag)
				if history == nil {
					continue
				}
				p := g.penaltyOf(tag)
				if choice == nil || p < minPenalty || (p == minPenalty && history.Delay < minDelay) {
					choice, minPenalty, minDelay = detour, p, history.Delay
				}
			}
			if choice != nil {
				return choice
			}
		}
		return nil
	}
	var best adapter.Outbound
	var bestPenalty int64
	var bestDelay uint16
	for _, detour := range g.outbounds {
		if !supportsNetwork(detour, network) {
			continue
		}
		realTag := RealTag(detour, N.NetworkTCP)
		if realTag == excludeTag || !g.guardAllows(realTag) {
			continue
		}
		history := g.history.LoadURLTestHistory(realTag)
		if history == nil {
			continue
		}
		penalty := g.penaltyOf(realTag)
		if best == nil || penalty < bestPenalty || (penalty == bestPenalty && history.Delay < bestDelay) {
			best = detour
			bestPenalty = penalty
			bestDelay = history.Delay
		}
	}
	return best
}

// selectPenaltyAware — Select с учётом штрафов: в аварийном режиме — двухуровневое
// ранжирование; иначе — апстримный Select как есть. Используется performUpdateCheck.
func (g *URLTestGroup) selectPenaltyAware(network string) (adapter.Outbound, bool) {
	// A responsive primary group must never lose to a faster whitelist fallback.
	if len(g.priorityOutbounds) > 0 {
		return g.selectPriority(network)
	}
	if g.balancer == nil && g.penaltyEmergency(network) {
		if best := g.penaltyBest(network, ""); best != nil {
			return best, true
		}
	}
	return g.Select(network)
}

// pickForDial — выбор узла для боевого дайла: аварийный режим обходит кеш
// selectedOutbound* (он может указывать на оштрафованного лучшего), обычный —
// апстримная семантика (кеш, иначе Select). lx: SPEC 139 — the pick is written
// to the connection test trace as a `group` stage.
func (g *URLTestGroup) pickForDial(ctx context.Context, network string) adapter.Outbound {
	outbound := g.pickForDialNode(network)
	g.traceGroup(ctx, outbound, "")
	return outbound
}

func (g *URLTestGroup) pickForDialNode(network string) adapter.Outbound {
	if len(g.priorityOutbounds) > 0 {
		preferred, _ := g.selectPriority(network)
		return preferred
	}
	if g.failover {
		// Keep a healthy held variant. If its history was invalidated by
		// another group, use the already healthy reserve instead of hiding
		// the whole logical node from its parent priority pool.
		expected := g.selectedForNetworkLx(network)
		selected, fresh := g.failoverSelect(network, false)
		if fresh && selected != nil && selected != expected {
			if _, applied := g.updateSelectedLx(network, expected, selected, true); applied {
				invalidateReachability(g.ctx)
				g.history.NotifyUpdated()
			} else {
				// A concurrent health update or another dial won the race.
				selected, _ = g.failoverSelect(network, false)
			}
		}
		return selected
	}
	if g.balancer == nil && g.penaltyEmergency(network) {
		if best := g.penaltyBest(network, ""); best != nil {
			return best
		}
	}
	tcp, udp := g.selectedLx()
	cached := tcp
	if network == N.NetworkUDP {
		cached = udp
	}
	if cached != nil && g.guardAllows(RealTag(cached, N.NetworkTCP)) {
		return cached
	}
	outbound, _ := g.Select(network)
	return outbound
}

// moveSelection переносит выбор на узел, доказавший жизнь fallback-дайлом.
// Без Interrupt: живые соединения не рвём; дерево достижимости (SPEC 020)
// инвалидируется, как при любом переизборе.
func (g *URLTestGroup) moveSelection(network string, detour adapter.Outbound) {
	if g.setSelectionLx(network, detour) {
		g.logger.Info("lx penalty: selection moved to ", detour.Tag(), " (", network, ")")
		invalidateReachability(g.ctx)
	}
}

// penaltyFailoverDial — обработка классифицированного отказа боевого дайла:
// штраф отказавшему, возможный аварийный force-прогон и ОДИН fallback-дайл
// (кап 2 попытки на пользовательский дайл — «обновят страницу, попробуем ещё»).
// Возвращает (conn, узел, true) при успехе fallback'а; иначе (nil, nil, false)
// и вызывающий отдаёт исходную ошибку приложению.
func (g *URLTestGroup) penaltyFailoverDial(ctx context.Context, network string, destination M.Socksaddr, failed adapter.Outbound, dialErr error) (net.Conn, adapter.Outbound, bool) {
	if g.balancer != nil || !g.pathDead(failed, dialErr) {
		return nil, nil, false
	}
	// lx: SPEC 139 §5.7 — a connection test takes the same fallback path but
	// leaves penalties, history, selection and the retest valve untouched.
	probe := lxtrace.IsProbe(ctx)
	if !probe {
		g.penaltyAdd(RealTag(failed, N.NetworkTCP))
		g.maybeForceRetest()
	}
	fallback := g.penaltyBest(network, RealTag(failed, N.NetworkTCP))
	if fallback == nil {
		return nil, nil, false
	}
	g.traceGroup(ctx, fallback, failed.Tag())
	// lx: SPEC 165 — the fallback pick goes through the same hook (carrier, Х8).
	leafCtx, fallbackDialer, err := adapter.ResolveChainLeaf(ctx, fallback)
	if err != nil {
		return nil, nil, false
	}
	var conn net.Conn
	if !probe && N.NetworkName(network) == N.NetworkTCP && g.passiveGuard != nil {
		conn, err = g.guardDial(leafCtx, RealTag(fallback, N.NetworkTCP), destination.String(), penaltySiteOnOpen(ctx, g.outbound, fallbackDialer), func() (net.Conn, error) {
			return fallbackDialer.DialContext(leafCtx, network, destination)
		})
	} else {
		conn, err = fallbackDialer.DialContext(leafCtx, network, destination)
	}
	if err != nil {
		g.logger.Error("lx penalty: fallback via ", fallback.Tag(), ": ", E.Cause(err, "dial"))
		if probe || E.IsClosedOrCanceled(err) {
			return nil, nil, false
		}
		// Симметрия с апстримным поведением least_test для отказавшего дайла.
		g.history.DeleteURLTestHistory(RealTag(fallback, N.NetworkTCP))
		if g.pathDead(fallbackDialer, err) {
			g.penaltyAdd(RealTag(fallback, N.NetworkTCP))
			g.maybeForceRetest()
		}
		return nil, nil, false
	}
	if !probe {
		g.penaltyReset(RealTag(fallback, N.NetworkTCP))
		g.moveSelection(network, fallback)
	}
	return conn, fallback, true
}

// maybeForceRetest — аварийный клапан: если среди кандидатов с history нет ни
// одного со штрафом < порога (умер путь целиком, ранжирование бессмысленно) —
// немедленный force-прогон проб. Уровень-триггер с дельта-лимитом
// penaltyForcedRetestGap от КОНЦА прошлого прогона; параллельные прогоны
// схлопывает существующий checking-CAS. Регулярный тикер при этом продолжает
// свой ритм: у мёртвых узлов history удалена, их перепробуют каждый interval.
func (g *URLTestGroup) maybeForceRetest() {
	if g.balancer != nil || !g.penaltyTotal(N.NetworkTCP) {
		return
	}
	last := g.lastForcedRetest.Load()
	if !last.IsZero() && time.Since(last) < penaltyForcedRetestGap {
		return
	}
	if !g.forcedRetestRunning.CompareAndSwap(false, true) {
		return
	}
	g.logger.Warn("lx penalty: all candidates penalized, forcing a retest")
	go func() {
		g.CheckOutbounds(g.ctx, true)
		// Отсчёт паузы от последнего ответа проб, не от старта прогона: длинный
		// прогон по большой мёртвой группе не должен позволять следующему шторму
		// стартовать впритык к концу этого.
		g.lastForcedRetest.Store(time.Now())
		g.forcedRetestRunning.Store(false)
	}()
}

// penaltyTotal — «тотальные штрафы»: есть кандидаты с history, и все ≥ порога.
func (g *URLTestGroup) penaltyTotal(network string) bool {
	var sawCandidate bool
	for _, detour := range g.outbounds {
		if !supportsNetwork(detour, network) {
			continue
		}
		realTag := RealTag(detour, N.NetworkTCP)
		if g.history.LoadURLTestHistory(realTag) == nil || !g.guardAllows(realTag) {
			continue
		}
		sawCandidate = true
		if g.penaltyOf(realTag) < penaltyThreshold {
			return false
		}
	}
	return sawCandidate
}

func supportsNetwork(detour adapter.Outbound, network string) bool {
	for _, n := range detour.Network() {
		if n == network {
			return true
		}
	}
	return false
}

// lx:end SPEC 054
