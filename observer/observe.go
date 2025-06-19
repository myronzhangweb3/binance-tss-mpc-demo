package observer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"binance-tss-mpc-server/common"
	"binance-tss-mpc-server/common/cosmos"
	"binance-tss-mpc-server/config"
	"binance-tss-mpc-server/constants"
	"binance-tss-mpc-server/metrics"
	"binance-tss-mpc-server/pkg/chainclients"
	"binance-tss-mpc-server/pubkeymanager"
	"binance-tss-mpc-server/thorclient"
	"binance-tss-mpc-server/thorclient/types"
	stypes "binance-tss-mpc-server/x/thorchain/types"
)

// signedTxOutCacheSize is the number of signed tx out observations to keep in memory
// to prevent duplicate observations. Based on historical data at the time of writing,
// the peak of Thorchain's L1 swaps was 10k per day.
const signedTxOutCacheSize = 10_000

// deckRefreshTime is the time to wait before reconciling txIn status.
const deckRefreshTime = 1 * time.Second

type txInKey struct {
	chain  common.Chain
	height int64
}

func TxInKey(txIn *types.TxIn) txInKey {
	return txInKey{
		chain:  txIn.Chain,
		height: txIn.TxArray[0].BlockHeight + txIn.ConfirmationRequired,
	}
}

// Observer observer service
type Observer struct {
	logger                zerolog.Logger
	chains                map[common.Chain]chainclients.ChainClient
	stopChan              chan struct{}
	pubkeyMgr             *pubkeymanager.PubKeyManager
	onDeck                map[txInKey]*types.TxIn
	lock                  *sync.Mutex
	globalTxsQueue        chan types.TxIn
	globalErrataQueue     chan types.ErrataBlock
	globalSolvencyQueue   chan types.Solvency
	globalNetworkFeeQueue chan common.NetworkFee
	m                     *metrics.Metrics
	errCounter            *prometheus.CounterVec
	thorchainBridge       thorclient.ThorchainBridge
	storage               *ObserverStorage
	tssKeysignMetricMgr   *metrics.TssKeysignMetricMgr

	// signedTxOutCache is a cache to keep track of observations for outbounds which were
	// manually observed after completion of signing and should be filtered from future
	// mempool and block observations.
	signedTxOutCache   *lru.Cache
	signedTxOutCacheMu sync.Mutex
	attestationGossip  *AttestationGossip

	observerWorkers int

	lastNodeStatus   stypes.NodeStatus
	lastNodeStatusMu sync.RWMutex

	deckDumpFile string
}

// NewObserver create a new instance of Observer for chain
func NewObserver(pubkeyMgr *pubkeymanager.PubKeyManager,
	chains map[common.Chain]chainclients.ChainClient,
	thorchainBridge thorclient.ThorchainBridge,
	m *metrics.Metrics, dataPath string,
	tssKeysignMetricMgr *metrics.TssKeysignMetricMgr,
	attestationGossip *AttestationGossip,
	deckDumpFile string,
) (*Observer, error) {
	logger := log.Logger.With().Str("module", "observer").Logger()

	cfg := config.GetBifrost()

	observerWorkers := cfg.ObserverWorkers
	if observerWorkers == 0 {
		observerWorkers = runtime.NumCPU() / 2
		if observerWorkers == 0 {
			observerWorkers = 1
		}
	}

	storage, err := NewObserverStorage(dataPath, cfg.ObserverLevelDB)
	if err != nil {
		return nil, fmt.Errorf("failed to create observer storage: %w", err)
	}

	if tssKeysignMetricMgr == nil {
		return nil, fmt.Errorf("tss keysign manager is nil")
	}

	signedTxOutCache, err := lru.New(signedTxOutCacheSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create signed tx out cache: %w", err)
	}

	return &Observer{
		logger:                logger,
		chains:                chains,
		stopChan:              make(chan struct{}),
		m:                     m,
		pubkeyMgr:             pubkeyMgr,
		lock:                  &sync.Mutex{},
		onDeck:                make(map[txInKey]*types.TxIn),
		globalTxsQueue:        make(chan types.TxIn),
		globalErrataQueue:     make(chan types.ErrataBlock),
		globalSolvencyQueue:   make(chan types.Solvency),
		globalNetworkFeeQueue: make(chan common.NetworkFee),
		errCounter:            m.GetCounterVec(metrics.ObserverError),
		thorchainBridge:       thorchainBridge,
		storage:               storage,
		tssKeysignMetricMgr:   tssKeysignMetricMgr,
		signedTxOutCache:      signedTxOutCache,
		attestationGossip:     attestationGossip,
		observerWorkers:       observerWorkers,
		deckDumpFile:          deckDumpFile,
	}, nil
}

func (o *Observer) getChain(chainID common.Chain) (chainclients.ChainClient, error) {
	chain, ok := o.chains[chainID]
	if !ok {
		o.logger.Debug().Str("chain", chainID.String()).Msg("is not supported yet")
		return nil, errors.New("not supported")
	}
	return chain, nil
}

func (o *Observer) Start(ctx context.Context) error {
	o.restoreDeck()
	for _, chain := range o.chains {
		chain.Start(o.globalTxsQueue, o.globalErrataQueue, o.globalSolvencyQueue, o.globalNetworkFeeQueue)
	}
	go o.processTxIns()
	go o.processErrataTx(ctx)
	go o.processSolvencyQueue(ctx)
	go o.processNetworkFeeQueue(ctx)
	go o.deck(ctx)
	go o.attestationGossip.Start(ctx)
	return nil
}

// ObserveSigned is called when a tx is signed by the signer and returns an observation that should be immediately submitted.
// Observations passed to this method with 'allowFutureObservation' false will be cached in memory and skipped if they are later observed in the mempool or block.
func (o *Observer) ObserveSigned(txIn types.TxIn) {
	if !txIn.AllowFutureObservation {
		// add all transaction ids to the signed tx out cache
		o.signedTxOutCacheMu.Lock()
		for _, tx := range txIn.TxArray {
			o.signedTxOutCache.Add(tx.Tx, nil)
		}
		o.signedTxOutCacheMu.Unlock()
	}

	o.globalTxsQueue <- txIn
}

// restoreDeck initializes the memory cache with the ondeck txs from the storage
func (o *Observer) restoreDeck() {
	onDeckTxs, err := o.storage.GetOnDeckTxs()
	if err != nil {
		o.logger.Error().Err(err).Msg("fail to restore ondeck txs")
	}

	if o.deckDumpFile != "" {
		// dump the ondeck txs to a file for debugging
		o.logger.Info().Msgf("dumping ondeck txs to %s", o.deckDumpFile)
		dumpTxs, err := json.Marshal(onDeckTxs)
		if err != nil {
			o.logger.Error().Err(err).Msg("fail to marshal ondeck txs")
		} else {
			if err := os.WriteFile(o.deckDumpFile, dumpTxs, 0o600); err != nil {
				o.logger.Error().Err(err).Msg("fail to write ondeck txs to file")
			}
			o.logger.Info().Msgf("ondeck txs dumped to %s", o.deckDumpFile)
		}
	}

	o.lock.Lock()
	defer o.lock.Unlock()
	for _, txIn := range onDeckTxs {
		o.onDeck[TxInKey(txIn)] = txIn
	}
}

func (o *Observer) deck(ctx context.Context) {
	for {
		select {
		case <-o.stopChan:
			o.sendDeck(ctx)
			return
		case <-time.After(deckRefreshTime):
			o.sendDeck(ctx)
		}
	}
}

// handleObservedTxCommitted will be called when an observed tx has been committed to thorchain,
// notified via AttestationGossip's grpc subscription to thornode..
func (o *Observer) handleObservedTxCommitted(tx common.ObservedTx) {
	madeChanges := false

	isFinal := tx.IsFinal()

	o.lock.Lock()
	defer o.lock.Unlock()

	k := txInKey{
		chain:  tx.Tx.Chain,
		height: tx.FinaliseHeight,
	}

	deck, ok := o.onDeck[k]
	if !ok {
		return
	}

	for j, txInItem := range deck.TxArray {
		if !txInItem.EqualsObservedTx(tx) {
			continue
		}
		if isFinal {
			o.logger.Debug().Msgf("tx final %s - %s removing from tx array", tx.Tx.Chain, tx.Tx.ID)
			// if the tx is in the tx array, and it is final, remove it from the tx array.
			deck.TxArray = slices.Delete(deck.TxArray, j, j+1)
			if len(deck.TxArray) == 0 {
				o.logger.Debug().Msgf("deck is empty, removing from ondeck")

				// if the deck is empty after removing, remove it from ondeck.
				delete(o.onDeck, k)
				if err := o.storage.RemoveTx(deck, tx.FinaliseHeight); err != nil {
					o.logger.Error().Err(err).Msg("fail to remove tx from storage")
				}
			} else {
				if j == 0 {
					// update block confirmation count
					deck.ConfirmationRequired = k.height - deck.TxArray[0].BlockHeight
				}
				if err := o.storage.AddOrUpdateTx(deck); err != nil {
					o.logger.Error().Err(err).Msg("fail to update tx in storage")
				}
			}
		} else {
			// if the tx is not final, set tx.CommittedUnFinalised to true to indicate that it has been committed to thorchain but not finalised yet.
			txInItem.CommittedUnFinalised = true
			if err := o.storage.AddOrUpdateTx(deck); err != nil {
				o.logger.Error().Err(err).Msg("fail to update tx in storage")
			}
		}

		chain, err := o.getChain(deck.Chain)
		if err != nil {
			o.logger.Error().Err(err).Msg("chain not found")
		} else {
			chain.OnObservedTxIn(*txInItem, txInItem.BlockHeight)
		}

		madeChanges = true
		break
	}

	if !madeChanges {
		o.logger.Debug().Msgf("no changes made to ondeck, size: %d", len(o.onDeck))
		return
	}

	o.logger.Debug().
		Int("ondeck_size", len(o.onDeck)).
		Str("id", tx.Tx.ID.String()).
		Str("chain", tx.Tx.Chain.String()).
		Int64("height", tx.BlockHeight).
		Str("from", tx.Tx.FromAddress.String()).
		Str("to", tx.Tx.ToAddress.String()).
		Str("memo", tx.Tx.Memo).
		Str("coins", tx.Tx.Coins.String()).
		Str("gas", common.Coins(tx.Tx.Gas).String()).
		Str("observed_vault_pubkey", tx.ObservedPubKey.String()).
		Msg("observed tx committed to thorchain")
}

func (o *Observer) sendDeck(ctx context.Context) {
	// fetch and update active validator count on attestation gossip so it can calculate quorum
	activeVals, err := o.thorchainBridge.FetchActiveNodes()
	if err != nil {
		o.logger.Error().Err(err).Msg("failed to get active node count")
		return
	}
	o.attestationGossip.setActiveValidators(activeVals)

	// check if node is active
	nodeStatus, err := o.thorchainBridge.FetchNodeStatus()
	if err != nil {
		o.logger.Error().Err(err).Msg("failed to get node status")
		return
	}
	o.lastNodeStatusMu.RLock()
	lastNodeStatus := o.lastNodeStatus
	o.lastNodeStatusMu.RUnlock()
	if nodeStatus != lastNodeStatus {
		o.lastNodeStatusMu.Lock()
		o.lastNodeStatus = nodeStatus
		o.lastNodeStatusMu.Unlock()

		if nodeStatus == stypes.NodeStatus_Active {
			o.logger.Info().Msg("node is now active, will begin observation and gossip")
			o.attestationGossip.askForAttestationState(ctx)
			if lastNodeStatus != stypes.NodeStatus_Unknown {
				// if this is not the first startup, we just churned in. rollback block scanners to re-observe recent blocks
				for _, chain := range o.chains {
					if err := chain.RollbackBlockScanner(); err != nil {
						o.logger.Error().Err(err).Msg("fail to rollback chain")
					}
				}
			}
		} else {
			o.lock.Lock()
			o.onDeck = make(map[txInKey]*types.TxIn)
			o.lock.Unlock()
			if err := o.storage.RemoveAllTxs(); err != nil {
				o.logger.Error().Err(err).Msg("fail to remove all tx from storage")
			}
		}
	}
	if nodeStatus != stypes.NodeStatus_Active {
		o.logger.Warn().Msg("node is not active, will not handle tx in")
		return
	}

	o.lock.Lock()
	defer o.lock.Unlock()

	for k, deck := range o.onDeck {
		chainClient, err := o.getChain(deck.Chain)
		if err != nil {
			o.logger.Error().Err(err).Msg("fail to retrieve chain client")
			continue
		}

		final := chainClient.ConfirmationCountReady(*deck)
		o.sendToQuorumChecker(deck, final, k.height)
	}
}

func (o *Observer) sendToQuorumChecker(deck *types.TxIn, finalised bool, finaliseHeight int64) {
	txs, err := o.getThorchainTxIns(deck, finalised, finaliseHeight)
	if err != nil {
		o.logger.Error().Err(err).Msg("fail to convert txin to thorchain txins")
		return
	}

	if len(txs) == 0 {
		// no tx to send
		return
	}

	inbound, outbound, err := o.thorchainBridge.GetInboundOutbound(txs)
	if err != nil {
		o.logger.Error().Err(err).Msg("fail to get inbound and outbound txs")
		return
	}

	for _, tx := range inbound {
		if err := o.attestationGossip.AttestObservedTx(context.Background(), &tx, true); err != nil {
			o.logger.Err(err).Msg("fail to send inbound tx to thorchain")
		}
	}

	for _, tx := range outbound {
		if err := o.attestationGossip.AttestObservedTx(context.Background(), &tx, false); err != nil {
			o.logger.Err(err).Msg("fail to send outbound tx to thorchain")
		}
	}
}

func (o *Observer) processTxIns() {
	// Create a worker pool with a reasonable number of workers
	// We can use runtime.NumCPU() to get the number of available CPUs
	// but let's limit the workers to avoid overwhelming the system

	// Create a semaphore to limit concurrency
	sem := make(chan struct{}, o.observerWorkers)

	for {
		select {
		case <-o.stopChan:
			// Wait for any running goroutines to complete
			for range o.observerWorkers {
				sem <- struct{}{}
			}
			return
		case txIn := <-o.globalTxsQueue:
			o.lastNodeStatusMu.RLock()
			lastNodeStatus := o.lastNodeStatus
			o.lastNodeStatusMu.RUnlock()

			if lastNodeStatus != stypes.NodeStatus_Active {
				continue
			}

			// Check if there are any items to process
			if len(txIn.TxArray) == 0 {
				continue
			}

			// Acquire a token from semaphore
			sem <- struct{}{}

			// Process observed tx in a goroutine
			go func(tx types.TxIn) {
				defer func() {
					// Release the token back to semaphore when done
					<-sem
				}()

				start := time.Now()
				o.processObservedTx(tx)
				o.logger.Debug().Msgf("processObservedTx took %s", time.Since(start))
			}(txIn)
		}
	}
}

// processObservedTx will process the observed tx, and either add it to the
// onDeck queue, or merge it with an existing tx in the onDeck queue.
func (o *Observer) processObservedTx(txIn types.TxIn) {
	if len(txIn.TxArray) == 0 {
		return
	}

	// Create a new slice for filtered transactions
	var filteredTxArray []*types.TxInItem

	// Check if we need to filter the incoming transactions
	if !txIn.Filtered {
		filterStart := time.Now()
		// First, get a read lock to check existing transactions
		// Filter without modifying shared state
		filteredTxArray = o.filterObservations(txIn.Chain, txIn.TxArray, txIn.MemPool)
		if len(filteredTxArray) == 0 {
			o.logger.Debug().Msgf("txin is empty after filtering, ignore it")
			return
		}

		// Set the filtered flag and update TxArray
		txIn.TxArray = filteredTxArray
		txIn.Filtered = true

		// If we're creating a new deck entry, set the confirmation required
		chainClient, err := o.getChain(txIn.Chain)
		if err == nil {
			txIn.ConfirmationRequired = chainClient.GetConfirmationCount(txIn)
		} else {
			o.logger.Error().Err(err).Msg("fail to get chain client for confirmation count")
		}
		o.logger.Debug().Msgf("filterObservations took %s", time.Since(filterStart))
	}

	k := TxInKey(&txIn)

	// Now acquire a write lock for modifying the onDeck slice
	o.lock.Lock()
	defer o.lock.Unlock()

	in, ok := o.onDeck[k]
	if ok {
		// tx is already in the onDeck, dedupe incoming txs
		dedupeStart := time.Now()
		var newTxs []*types.TxInItem
		for _, txInItem := range txIn.TxArray {
			foundTx := false
			for _, txInItemDeck := range in.TxArray {
				if txInItemDeck.Equals(txInItem) {
					foundTx = true
					o.logger.Warn().
						Str("id", txInItem.Tx).
						Str("chain", in.Chain.String()).
						Int64("height", txInItem.BlockHeight).
						Str("from", txInItem.Sender).
						Str("to", txInItem.To).
						Str("memo", txInItem.Memo).
						Str("coins", txInItem.Coins.String()).
						Str("gas", common.Coins(txInItem.Gas).String()).
						Str("observed_vault_pubkey", txInItem.ObservedVaultPubKey.String()).
						Msg("Dropping duplicate observation tx")
					break
				}
			}
			if !foundTx {
				newTxs = append(newTxs, txInItem)
			}
		}
		o.logger.Debug().Msgf("Dedupe took %s", time.Since(dedupeStart))
		if len(newTxs) > 0 {
			in.TxArray = append(in.TxArray, newTxs...)
			setDeckStart := time.Now()
			if err := o.storage.AddOrUpdateTx(in); err != nil {
				o.logger.Error().Err(err).Msg("fail to add tx to storage")
			}
			o.logger.Debug().Msgf("AddOrUpdateTx existing took %s", time.Since(setDeckStart))
		}

		return
	}
	o.onDeck[k] = &txIn

	setDeckStart := time.Now()
	if err := o.storage.AddOrUpdateTx(&txIn); err != nil {
		o.logger.Error().Err(err).Msg("fail to add tx to storage")
	}
	o.logger.Debug().Msgf("AddOrUpdateTx new took %s", time.Since(setDeckStart))
}

func (o *Observer) filterObservations(chain common.Chain, items []*types.TxInItem, memPool bool) []*types.TxInItem {
	var txs []*types.TxInItem
	for _, txInItem := range items {
		// NOTE: the following could result in the same tx being added
		// twice, which is expected. We want to make sure we generate both
		// a inbound and outbound txn, if we both apply.

		isInternal := false
		// check if the from address is a valid pool
		if ok, cpi := o.pubkeyMgr.IsValidPoolAddress(txInItem.Sender, chain); ok {
			tx := txInItem.Copy()
			tx.ObservedVaultPubKey = cpi.PubKey
			isInternal = true

			// skip the outbound observation if we signed and manually observed
			o.signedTxOutCacheMu.Lock()
			hasSigned := o.signedTxOutCache.Contains(tx.Tx)
			o.signedTxOutCacheMu.Unlock()
			if !hasSigned {
				txs = append(txs, tx)
			}
		}
		// check if the to address is a valid pool address
		// for inbound message , if it is still in mempool , it will be ignored unless it is internal transaction
		// internal tx means both from & to addresses belongs to the network. for example migrate/consolidate
		if ok, cpi := o.pubkeyMgr.IsValidPoolAddress(txInItem.To, chain); ok && (!memPool || isInternal) {
			tx := txInItem.Copy()
			tx.ObservedVaultPubKey = cpi.PubKey
			txs = append(txs, tx)
		}
	}
	return txs
}

func (o *Observer) processErrataTx(ctx context.Context) {
	for {
		select {
		case <-o.stopChan:
			return
		case errataBlock, more := <-o.globalErrataQueue:
			if !more {
				return
			}
			// filter
			o.filterErrataTx(errataBlock)
			o.logger.Info().Msgf("Received a errata block %+v from the Thorchain", errataBlock.Height)
			for _, errataTx := range errataBlock.Txs {
				if err := o.attestationGossip.AttestErrata(ctx, common.ErrataTx{
					Chain: errataTx.Chain,
					Id:    errataTx.TxID,
				}); err != nil {
					o.errCounter.WithLabelValues("fail_to_broadcast_errata_tx", "").Inc()
					o.logger.Error().Err(err).Msg("fail to broadcast errata tx")
				}
			}
		}
	}
}

// filterErrataTx with confirmation counting logic in place, all inbound tx to asgard will be parked and waiting for confirmation count to reach
// the target threshold before it get forward to THORChain,  it is possible that when a re-org happened on BTC / ETH
// the transaction that has been re-org out ,still in bifrost memory waiting for confirmation, as such, it should be
// removed from ondeck tx queue, and not forward it to THORChain
func (o *Observer) filterErrataTx(block types.ErrataBlock) {
	o.lock.Lock()
	defer o.lock.Unlock()
BlockLoop:
	for _, tx := range block.Txs {
		for k, txIn := range o.onDeck {
			for i, item := range txIn.TxArray {
				if item.Tx == tx.TxID.String() {
					o.logger.Info().Msgf("drop tx (%s) from ondeck memory due to errata", tx.TxID)
					txIn.TxArray = append(txIn.TxArray[:i], txIn.TxArray[i+1:]...) // nolint
					if len(txIn.TxArray) == 0 {
						o.logger.Info().Msgf("ondeck tx is empty, remove it from ondeck")
						delete(o.onDeck, k)
						if err := o.storage.RemoveTx(txIn, block.Height); err != nil {
							o.logger.Error().Err(err).Msg("fail to remove tx from storage")
						}
					} else {
						if i == 0 {
							// update block confirmation count
							txIn.ConfirmationRequired = k.height - txIn.TxArray[0].BlockHeight
						}
						if err := o.storage.AddOrUpdateTx(txIn); err != nil {
							o.logger.Error().Err(err).Msg("fail to update tx in storage")
						}
					}
					break BlockLoop
				}
			}
		}
	}
}

// getSaversMemo returns an add or withdraw memo for a Savers Vault
// If the tx is not a valid savers tx, an empty string will be returned
// Savers tx criteria:
// - Inbound amount must be gas asset
// - Inbound amount must be greater than the Dust Threshold of the tx chain (see chain.DustThreshold())
func (o *Observer) getSaversMemo(chain common.Chain, tx *types.TxInItem) string {
	// Savers txs should have one Coin input
	if len(tx.Coins) != 1 {
		return ""
	}

	txAmt := tx.Coins[0].Amount
	dustThreshold := chain.DustThreshold()

	// Below dust threshold, ignore
	if txAmt.LT(dustThreshold) {
		return ""
	}

	asset := tx.Coins[0].Asset
	synthAsset := asset.GetSyntheticAsset()
	bps := txAmt.Sub(dustThreshold)

	switch {
	case bps.IsZero():
		// Amount is too low, ignore
		return ""
	case bps.LTE(cosmos.NewUint(10_000)):
		// Amount is within or includes dustThreshold + 10_000, generate withdraw memo
		return fmt.Sprintf("-:%s:%s", synthAsset.String(), bps.String())
	default:
		// Amount is above dustThreshold + 10_000, generate add memo
		return fmt.Sprintf("+:%s", synthAsset.String())
	}
}

// getThorchainTxIns convert to the type thorchain expected
// maybe in later THORNode can just refactor this to use the type in thorchain
func (o *Observer) getThorchainTxIns(txIn *types.TxIn, finalized bool, finaliseHeight int64) (common.ObservedTxs, error) {
	obsTxs := make(common.ObservedTxs, 0, len(txIn.TxArray))
	o.logger.Debug().Msgf("len %d", len(txIn.TxArray))
	for _, item := range txIn.TxArray {
		if item.CommittedUnFinalised && !finalized {
			// we have already committed this tx in the un-finalized state,
			// and the tx is not yet final, so we should not send it again.
			continue
		}
		if item.Coins.IsEmpty() {
			o.logger.Info().Msgf("item(%+v) , coins are empty , so ignore", item)
			continue
		}
		if len([]byte(item.Memo)) > constants.MaxMemoSize {
			o.logger.Info().Msgf("tx (%s) memo (%s) too long", item.Tx, item.Memo)
			continue
		}

		// If memo is empty, see if it is a memo-less savers add or withdraw
		if strings.EqualFold(item.Memo, "") {
			memo := o.getSaversMemo(txIn.Chain, item)
			if !strings.EqualFold(memo, "") {
				o.logger.Info().Str("memo", memo).Str("txId", item.Tx).Msg("created savers memo")
				item.Memo = memo
			}
		}

		if len(item.To) == 0 {
			o.logger.Info().Msgf("tx (%s) to address is empty,ignore it", item.Tx)
			continue
		}
		o.logger.Debug().Str("tx-hash", item.Tx).Msg("txInItem")
		blockHeight := strconv.FormatInt(item.BlockHeight, 10)
		txID, err := common.NewTxID(item.Tx)
		if err != nil {
			o.errCounter.WithLabelValues("fail_to_parse_tx_hash", blockHeight).Inc()
			o.logger.Err(err).Msgf("fail to parse tx hash, %s is invalid", item.Tx)
			continue
		}
		sender, err := common.NewAddress(item.Sender)
		if err != nil {
			o.errCounter.WithLabelValues("fail_to_parse_sender", item.Sender).Inc()
			// log the error , and ignore the transaction, since the address is not valid
			o.logger.Err(err).Msgf("fail to parse sender, %s is invalid sender address", item.Sender)
			continue
		}

		to, err := common.NewAddress(item.To)
		if err != nil {
			o.errCounter.WithLabelValues("fail_to_parse_to", item.To).Inc()
			o.logger.Err(err).Msgf("fail to parse to, %s is invalid to address", item.To)
			continue
		}

		o.logger.Debug().Msgf("pool pubkey %s", item.ObservedVaultPubKey)
		chainAddr, err := item.ObservedVaultPubKey.GetAddress(txIn.Chain)
		o.logger.Debug().Msgf("%s address %s", txIn.Chain.String(), chainAddr)
		if err != nil {
			o.errCounter.WithLabelValues("fail to parse observed pool address", item.ObservedVaultPubKey.String()).Inc()
			o.logger.Err(err).Msgf("fail to parse observed pool address: %s", item.ObservedVaultPubKey.String())
			continue
		}
		height := item.BlockHeight
		if finalized {
			height = finaliseHeight
		}
		// Strip out any empty Coin from Coins and Gas, as even one empty Coin will make a MsgObservedTxIn for instance fail validation.
		tx := common.NewTx(txID, sender, to, item.Coins.NoneEmpty(), item.Gas.NoneEmpty(), item.Memo)
		obsTx := common.NewObservedTx(tx, height, item.ObservedVaultPubKey, finaliseHeight)
		obsTx.KeysignMs = o.tssKeysignMetricMgr.GetTssKeysignMetric(item.Tx)
		obsTx.Aggregator = item.Aggregator
		obsTx.AggregatorTarget = item.AggregatorTarget
		obsTx.AggregatorTargetLimit = item.AggregatorTargetLimit
		obsTxs = append(obsTxs, obsTx)
	}
	return obsTxs, nil
}

func (o *Observer) processSolvencyQueue(ctx context.Context) {
	for {
		select {
		case <-o.stopChan:
			return
		case solvencyItem, more := <-o.globalSolvencyQueue:
			if !more {
				return
			}
			if solvencyItem.Chain.IsEmpty() || solvencyItem.Coins.IsEmpty() || solvencyItem.PubKey.IsEmpty() {
				continue
			}
			o.logger.Debug().Msgf("solvency:%+v", solvencyItem)
			if err := o.attestationGossip.AttestSolvency(ctx, common.Solvency{
				Chain:  solvencyItem.Chain,
				Height: solvencyItem.Height,
				PubKey: solvencyItem.PubKey,
				Coins:  solvencyItem.Coins,
			}); err != nil {
				o.errCounter.WithLabelValues("fail_to_broadcast_solvency", "").Inc()
				o.logger.Error().Err(err).Msg("fail to broadcast solvency tx")
			}
		}
	}
}

func (o *Observer) processNetworkFeeQueue(ctx context.Context) {
	for {
		select {
		case <-o.stopChan:
			return
		case networkFee := <-o.globalNetworkFeeQueue:
			if err := networkFee.Valid(); err != nil {
				o.logger.Error().Err(err).Msgf("invalid network fee - %s", networkFee.String())
				continue
			}
			if err := o.attestationGossip.AttestNetworkFee(ctx, networkFee); err != nil {
				o.logger.Err(err).Msg("fail to send network fee to thorchain")
			}
		}
	}
}

// Stop the observer
func (o *Observer) Stop() error {
	o.logger.Debug().Msg("request to stop observer")
	defer o.logger.Debug().Msg("observer stopped")

	for _, chain := range o.chains {
		chain.Stop()
	}

	close(o.stopChan)
	if err := o.pubkeyMgr.Stop(); err != nil {
		o.logger.Error().Err(err).Msg("fail to stop pool address manager")
	}
	if err := o.storage.Close(); err != nil {
		o.logger.Err(err).Msg("fail to close observer storage")
	}
	return o.m.Stop()
}
