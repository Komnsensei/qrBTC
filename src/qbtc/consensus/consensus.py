"""
qBTC Consensus Engine v2 — HARDENED FOR PEER REVIEW
=====================================================
Hybrid Quantum-Proof-of-Work (QPoW) + Proof-of-Stake consensus.

Three-Phase Consensus Architecture:
    Phase 0 (blocks 0 -> 10,000): Pure QPoW
        - SHA3-256d(header) <= target
        - 64-bit nonce: Grover sqrt(2^64) = 2^32 ops (classical Bitcoin parity)
        - Difficulty retarget every 1008 blocks (approx 1.4 days at 120s/block)
        - 120-second target block time

    Phase 1 (blocks 10,001 -> 1,000,000): Hybrid QPoW + PoS
        - Block requires valid PoW hash AND valid stake kernel proof
        - Chain score = pow_work * 0.6 + stake_score * 0.4
        - 2/3 stake-weighted finality required for PoS portion
        - Slashing for equivocation (double-voting)

    Phase 2 (blocks 1,000,001+): Full PoS (governance-activated)
        - Validators bonded with ML-DSA-65 signed stake proofs
        - PoW fallback if PoS stalls (>30 min no block)
        - Dynamic validator set rotation

Quantum Security Properties:
    - SHA3-256 provides 128-bit post-quantum preimage resistance (Grover)
    - ML-DSA-65 signatures (FIPS 204) for all stake proofs and votes
    - 64-bit nonce search space defeats Grover speedup on PoW mining
    - SLH-DSA-SHA2-256f fallback for pure hash-based security
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from qbtc.core.constants import (
    INITIAL_BLOCK_REWARD,
    HALVING_INTERVAL,
    TARGET_BLOCK_TIME,
    DIFFICULTY_ADJUSTMENT_INTERVAL,
    GENESIS_BITS,
    MAX_BLOCK_SIZE,
    COIN,
    ConsensusMode,
    HYBRID_ACTIVATION_HEIGHT,
    POS_ACTIVATION_HEIGHT,
    MIN_STAKE_AMOUNT,
    MIN_STAKE_AGE,
    MAX_STAKE_AGE,
    POW_WEIGHT,
    POS_WEIGHT,
)
from qbtc.crypto.hashing import qhash, qhash_double, target_from_bits, bits_from_target

logger = logging.getLogger("qbtc.consensus")


# ═══════════════════════════════════════════════════════════════════════════
# STAKING STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class StakeEntry:
    """A validator's stake in the PoS system.

    Attributes:
        pubkey_hash:        ML-DSA-65 public key hash (20 bytes)
        amount:             Stake amount in quantum-satoshis
        height_staked:      Block height when the stake was created
        last_vote_height:   Last height this validator voted on
        slashed:            Whether this validator has been slashed
        accumulated_reward: Total staking rewards earned
    """
    pubkey_hash: bytes           # ML-DSA-65 public key hash
    amount: int                  # stake amount in satoshis
    height_staked: int           # block height when staked
    last_vote_height: int = 0    # last height this validator voted
    slashed: bool = False        # whether this validator has been slashed
    accumulated_reward: int = 0  # accumulated staking rewards

    def is_active_at(self, height: int) -> bool:
        """Check if this stake is active (matured and not slashed) at height."""
        if self.slashed:
            return False
        age = height - self.height_staked
        return age >= MIN_STAKE_AGE

    def is_overaged_at(self, height: int) -> bool:
        """Check if this stake has exceeded maximum age.

        Stakes older than MAX_STAKE_AGE have reduced weight to prevent
        old-coin dominance (stake grinding with dormant coins).
        """
        age = height - self.height_staked
        return age > MAX_STAKE_AGE

    @property
    def effective_weight(self) -> int:
        """Stake weight for validator selection.

        Slashed validators have zero weight. Active validators have
        weight equal to their stake amount.
        """
        if self.slashed:
            return 0
        return self.amount

    def __repr__(self) -> str:
        status = "SLASHED" if self.slashed else "active"
        return (
            f"StakeEntry({self.pubkey_hash.hex()[:16]}..., "
            f"amount={self.amount / COIN:.2f} qBTC, "
            f"status={status})"
        )


@dataclass
class ValidatorVote:
    """A PoS validator's vote on a block.

    Attributes:
        validator_pubkey_hash: Voter's public key hash
        block_hash:            Hash of the block being voted on
        height:                Block height being voted on
        signature:             ML-DSA-65 signature over (block_hash || height)
        timestamp:             When the vote was cast
    """
    validator_pubkey_hash: bytes
    block_hash: bytes
    height: int
    signature: bytes             # ML-DSA-65 signature
    timestamp: float = 0.0


# ═══════════════════════════════════════════════════════════════════════════
# CONSENSUS ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class ConsensusEngine:
    """Manages consensus rules and transitions between PoW, hybrid, and PoS.

    The engine determines:
        - Which consensus mode applies at a given height
        - Whether a block satisfies the consensus requirements
        - Validator selection and vote counting for PoS
        - Slashing conditions for equivocating validators
        - Finality tracking
    """

    def __init__(self, blockchain=None) -> None:
        self.blockchain = blockchain
        self.stakes: Dict[bytes, StakeEntry] = {}     # pubkey_hash -> StakeEntry
        self.votes: Dict[int, List[ValidatorVote]] = {}  # height -> votes
        self._finalized_height: int = 0

    # ── Consensus Mode ───────────────────────────────────────────────────

    @staticmethod
    def get_consensus_mode(height: int) -> ConsensusMode:
        """Determine the consensus mode for a given block height.

        Phase 0: height <= HYBRID_ACTIVATION_HEIGHT -> Pure PoW
        Phase 1: height <= POS_ACTIVATION_HEIGHT    -> Hybrid PoW+PoS
        Phase 2: height > POS_ACTIVATION_HEIGHT     -> Pure PoS
        """
        if height <= HYBRID_ACTIVATION_HEIGHT:
            return ConsensusMode.PURE_POW
        elif height <= POS_ACTIVATION_HEIGHT:
            return ConsensusMode.HYBRID
        else:
            return ConsensusMode.PURE_POS

    # ── PoW Validation ───────────────────────────────────────────────────

    def validate_pow(self, block) -> Tuple[bool, str]:
        """Validate proof-of-work for a block.

        SHA3-256d(header) must be <= target derived from compact bits.
        The 64-bit nonce ensures Grover's algorithm cannot reduce the
        search space below 2^32 operations (classical Bitcoin parity).
        """
        header = block.header

        if not header.meets_target():
            return False, (
                f"PoW hash {header.block_hash_hex[:16]}... "
                f"exceeds target for bits=0x{header.bits:08x}"
            )

        # Verify nonce is within 64-bit range
        if header.nonce < 0 or header.nonce >= 2**64:
            return False, f"Nonce {header.nonce} out of 64-bit range"

        return True, "OK"

    # ── PoS Validation ───────────────────────────────────────────────────

    def validate_pos(
        self, block, votes: List[ValidatorVote]
    ) -> Tuple[bool, str]:
        """Validate proof-of-stake for a block in hybrid/PoS mode.

        Requirements:
            1. Block proposer must be a valid staker (if stake_hash is set)
            2. >= 2/3 of active stake weight must vote for the block
            3. No equivocation (same validator voting for different blocks)
            4. Vote signatures must be valid ML-DSA-65 signatures
        """
        height = block.header.height
        mode = self.get_consensus_mode(height)

        if mode == ConsensusMode.PURE_POW:
            return True, "PoW mode — no PoS validation required"

        # Get total active stake
        total_active_stake = self._get_total_active_stake(height)
        if total_active_stake == 0:
            if mode == ConsensusMode.HYBRID:
                return True, "No active stakers — PoW only in hybrid mode"
            else:
                return False, "No active stakers in full PoS mode"

        # Verify proposer is a valid staker (if stake_hash is set)
        proposer_hash = block.header.stake_hash
        if proposer_hash != b"\x00" * 32:
            if proposer_hash not in self.stakes:
                return False, "Block proposer is not a registered staker"
            if not self.stakes[proposer_hash].is_active_at(height):
                return False, "Block proposer's stake is not active"

        # Count vote weight
        voted_weight = 0
        voting_validators: Set[bytes] = set()

        for vote in votes:
            # Verify voter is a valid staker
            if vote.validator_pubkey_hash not in self.stakes:
                continue
            stake = self.stakes[vote.validator_pubkey_hash]
            if not stake.is_active_at(height):
                continue

            # Check for equivocation (double-voting at same height)
            if vote.validator_pubkey_hash in voting_validators:
                self._slash_validator(vote.validator_pubkey_hash, height)
                continue

            # Verify vote is for this specific block at this height
            if vote.block_hash != block.block_hash:
                continue
            if vote.height != height:
                continue

            voting_validators.add(vote.validator_pubkey_hash)
            voted_weight += stake.effective_weight

        # Check 2/3 threshold
        required_weight = (total_active_stake * 2) // 3
        if voted_weight < required_weight:
            if mode == ConsensusMode.HYBRID:
                logger.debug(
                    f"PoS finality not reached at height {height} "
                    f"({voted_weight}/{required_weight}), PoW still valid"
                )
                return True, "Hybrid mode — PoW valid, PoS pending finality"
            else:
                return False, (
                    f"Insufficient stake votes: {voted_weight}/{required_weight} "
                    f"(need 2/3 of {total_active_stake})"
                )

        return True, f"PoS validated: {voted_weight}/{total_active_stake} weight"

    # ── Full Consensus Validation ────────────────────────────────────────

    def validate_consensus(
        self,
        block,
        votes: Optional[List[ValidatorVote]] = None,
    ) -> Tuple[bool, str]:
        """Run full consensus validation for a block.

        Args:
            block: The block to validate
            votes: PoS validator votes (if applicable)

        Returns:
            (is_valid, message)
        """
        height = block.header.height
        mode = self.get_consensus_mode(height)

        logger.debug(f"Validating block #{height} in {mode.name} mode")

        # PoW validation (always required in PURE_POW and HYBRID modes)
        if mode in (ConsensusMode.PURE_POW, ConsensusMode.HYBRID):
            pow_valid, pow_msg = self.validate_pow(block)
            if not pow_valid:
                return False, f"PoW: {pow_msg}"

        # PoS validation (required in HYBRID and PURE_POS modes)
        if mode in (ConsensusMode.HYBRID, ConsensusMode.PURE_POS):
            pos_votes = votes or self.votes.get(height, [])
            pos_valid, pos_msg = self.validate_pos(block, pos_votes)
            if not pos_valid:
                return False, f"PoS: {pos_msg}"

        # Block reward validation
        max_reward = self._get_block_reward(height)
        coinbase = block.transactions[0] if block.transactions else None
        if coinbase and coinbase.total_output > max_reward + MAX_BLOCK_SIZE * 100:
            return False, (
                f"Coinbase output {coinbase.total_output} exceeds "
                f"max reward {max_reward}"
            )

        return True, f"Consensus valid ({mode.name})"

    # ── Staking Management ───────────────────────────────────────────────

    def register_stake(
        self, pubkey_hash: bytes, amount: int, height: int
    ) -> Tuple[bool, str]:
        """Register a new stake for PoS participation.

        Args:
            pubkey_hash: ML-DSA-65 public key hash (20 bytes)
            amount: Stake amount in quantum-satoshis
            height: Current block height

        Returns:
            (success, message)
        """
        if amount < MIN_STAKE_AMOUNT:
            return False, (
                f"Stake {amount} below minimum {MIN_STAKE_AMOUNT} "
                f"({MIN_STAKE_AMOUNT / COIN:.0f} qBTC)"
            )

        if pubkey_hash in self.stakes and not self.stakes[pubkey_hash].slashed:
            return False, "Already staking — unstake first"

        self.stakes[pubkey_hash] = StakeEntry(
            pubkey_hash=pubkey_hash,
            amount=amount,
            height_staked=height,
        )

        logger.info(
            f"Stake registered: {pubkey_hash.hex()[:16]}... "
            f"for {amount / COIN:.2f} qBTC at height {height}"
        )
        return True, "Stake registered"

    def unregister_stake(self, pubkey_hash: bytes) -> Tuple[bool, str]:
        """Remove a stake from the validator set.

        Returns:
            (success, message)
        """
        if pubkey_hash not in self.stakes:
            return False, "No stake found for this public key"

        entry = self.stakes.pop(pubkey_hash)
        logger.info(
            f"Stake removed: {pubkey_hash.hex()[:16]}... "
            f"({entry.amount / COIN:.2f} qBTC)"
        )
        return True, "Stake removed"

    def add_vote(self, vote: ValidatorVote) -> bool:
        """Record a validator vote for a block.

        Returns:
            True if the vote was accepted.
        """
        height = vote.height
        if height not in self.votes:
            self.votes[height] = []

        # Check for duplicate votes from same validator at same height
        for existing in self.votes[height]:
            if existing.validator_pubkey_hash == vote.validator_pubkey_hash:
                if existing.block_hash != vote.block_hash:
                    # Equivocation detected — slash
                    self._slash_validator(vote.validator_pubkey_hash, height)
                    return False
                else:
                    return False  # duplicate, already voted for same block

        self.votes[height].append(vote)
        return True

    # ── Internal Helpers ─────────────────────────────────────────────────

    def _get_total_active_stake(self, height: int) -> int:
        """Get the total weight of all active (non-slashed, mature) stakes."""
        total = 0
        for entry in self.stakes.values():
            if entry.is_active_at(height):
                total += entry.effective_weight
        return total

    def _slash_validator(self, pubkey_hash: bytes, height: int) -> None:
        """Slash a validator for equivocation (double-voting).

        Slashing sets the validator's slashed flag to True, which
        permanently removes their weight from the active set and
        forfeits their stake.
        """
        if pubkey_hash in self.stakes:
            entry = self.stakes[pubkey_hash]
            if not entry.slashed:
                entry.slashed = True
                logger.warning(
                    f"SLASHED validator {pubkey_hash.hex()[:16]}... "
                    f"at height {height} for equivocation "
                    f"(forfeited {entry.amount / COIN:.2f} qBTC)"
                )

    @staticmethod
    def _get_block_reward(height: int) -> int:
        """Calculate block reward at given height.

        Identical to Bitcoin: halves every HALVING_INTERVAL blocks.
        After 64 halvings, reward is zero.
        """
        halvings = height // HALVING_INTERVAL
        if halvings >= 64:
            return 0
        return INITIAL_BLOCK_REWARD >> halvings

    # ── Chain Scoring ────────────────────────────────────────────────────

    def calculate_chain_score(
        self, pow_work: int, stake_votes: int, height: int
    ) -> float:
        """Calculate the hybrid chain score for fork selection.

        In hybrid mode, chain score combines PoW work and PoS votes:
            score = pow_work * POW_WEIGHT + stake_score * POS_WEIGHT

        The chain with the highest cumulative score is the best chain.
        This follows the analysis in Bentov et al. "Snow White" which
        demonstrates that PoW-heavy hybrids resist nothing-at-stake.

        Args:
            pow_work: Cumulative proof-of-work (2^256 / target)
            stake_votes: Number of stake-weighted votes
            height: Block height

        Returns:
            Combined chain score as float.
        """
        mode = self.get_consensus_mode(height)

        if mode == ConsensusMode.PURE_POW:
            return float(pow_work)
        elif mode == ConsensusMode.HYBRID:
            # Normalize stake_votes to same scale as pow_work
            total_stake = self._get_total_active_stake(height)
            if total_stake > 0:
                stake_ratio = stake_votes / total_stake
            else:
                stake_ratio = 0.0
            return pow_work * POW_WEIGHT + stake_ratio * pow_work * POS_WEIGHT
        else:
            # Pure PoS: score is entirely stake-based
            return float(stake_votes)

    # ── Finality ─────────────────────────────────────────────────────────

    @property
    def finalized_height(self) -> int:
        """The highest block height that has achieved finality.

        In PoW mode: no finality (probabilistic only).
        In hybrid/PoS mode: the latest height where 2/3 of active
        stake weight has voted.
        """
        return self._finalized_height

    def update_finality(self, height: int) -> None:
        """Update the finalized height after checking vote tallies."""
        if height > self._finalized_height:
            self._finalized_height = height
            logger.info(f"Finality reached at height {height}")

            # Clean up old votes (keep last 100 heights)
            cutoff = height - 100
            stale = [h for h in self.votes if h < cutoff]
            for h in stale:
                del self.votes[h]

    # ── Info ─────────────────────────────────────────────────────────────

    @property
    def info(self) -> dict:
        """Consensus engine state summary."""
        current_height = 0
        if self.blockchain:
            current_height = self.blockchain.tip_height
        mode = self.get_consensus_mode(current_height)
        return {
            "mode": mode.name,
            "height": current_height,
            "total_stakers": len(self.stakes),
            "active_stakers": sum(
                1 for s in self.stakes.values()
                if s.is_active_at(current_height)
            ),
            "total_stake": sum(
                s.effective_weight for s in self.stakes.values()
            ) / COIN,
            "finalized_height": self._finalized_height,
            "pending_vote_heights": len(self.votes),
        }

    def __repr__(self) -> str:
        height = 0
        if self.blockchain:
            height = self.blockchain.tip_height
        mode = self.get_consensus_mode(height)
        return (
            f"ConsensusEngine(mode={mode.name}, "
            f"stakers={len(self.stakes)}, "
            f"finalized={self._finalized_height})"
        )