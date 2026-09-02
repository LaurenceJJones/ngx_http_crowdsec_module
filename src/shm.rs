//! Shared memory implementation for CrowdSec decisions
//!
//! This module provides a high-performance shared memory store that is accessible across all
//! NGINX worker processes. It uses:
//! - Hash table with open addressing for O(1) IP lookups
//! - CIDR/range support via netmask-based lookup (like the Lua bouncer)
//! - Clock-based LRU eviction when capacity is reached
//! - Dynamic capacity based on configured SHM size

use ngx::ffi::{
    NGX_OK, ngx_atomic_t, ngx_int_t, ngx_rwlock_rlock, ngx_rwlock_unlock, ngx_rwlock_wlock,
    ngx_shm_zone_t, ngx_slab_alloc_locked, ngx_slab_pool_t, ngx_str_t,
};
use ngx::ngx_string;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum number of unique scenarios (most deployments have <100)
const MAX_SCENARIOS: usize = 256;

/// Maximum length of a scenario string
const MAX_SCENARIO_LEN: usize = 127;

/// Magic at the start of [`ShmData`] (`b"CsD1"`).
const SHM_MAGIC: u32 = u32::from_le_bytes(*b"CsD1");

/// Increment when `ShmData` / `ShmHashEntry` / string table layout changes incompatibly.
/// Reload reuses the zone pointer only when this matches; otherwise require a full restart.
const SHM_LAYOUT_VERSION: u32 = 2;

/// Percentage of SHM to use for entries (rest is overhead)
const USABLE_MEMORY_PERCENT: usize = 70;

/// Minimum hash table capacity
const MIN_CAPACITY: u32 = 1024;

/// Empty hash slot marker
const HASH_EMPTY: u32 = 0;

/// Tombstone marker for deleted entries
const HASH_TOMBSTONE: u32 = 1;

/// Flag bits in the flags field
const FLAG_TOMBSTONE: u8 = 0b0000_0001;
const FLAG_IS_CIDR: u8 = 0b0000_0100;

/// Decision types from CrowdSec
/// These are used both as enum values and as bitmask values
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionType {
    /// Ban - block the request entirely (highest priority)
    Ban = 1,
    /// Captcha - require captcha verification
    Captcha = 2,
    /// Unknown - fallback for future/unsupported types
    Unknown = 255,
}

/// Bitmask constants for decision types
/// Multiple decisions can be active for the same IP
pub const DECISION_BIT_BAN: u8 = 0b0000_0001;
pub const DECISION_BIT_CAPTCHA: u8 = 0b0000_0010;

impl DecisionType {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "ban" => DecisionType::Ban,
            "captcha" => DecisionType::Captcha,
            _ => DecisionType::Unknown,
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => DecisionType::Ban,
            2 => DecisionType::Captcha,
            _ => DecisionType::Unknown,
        }
    }

    /// Convert decision type to its bitmask value
    pub fn to_bit(self) -> u8 {
        match self {
            DecisionType::Ban => DECISION_BIT_BAN,
            DecisionType::Captcha => DECISION_BIT_CAPTCHA,
            DecisionType::Unknown => 0,
        }
    }

    /// Get the highest priority decision type from a bitmask
    /// Priority: Ban > Captcha
    pub fn from_bitmask(bits: u8) -> Self {
        if bits & DECISION_BIT_BAN != 0 {
            DecisionType::Ban
        } else if bits & DECISION_BIT_CAPTCHA != 0 {
            DecisionType::Captcha
        } else {
            DecisionType::Unknown
        }
    }
}

/// Origin of the decision
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// CrowdSec agent detection
    Crowdsec = 1,
    /// Manual via cscli or cscli-import
    Cscli = 2,
    /// Central API (CAPI)
    Capi = 3,
    /// Web console
    Console = 4,
    /// Blocklists
    Lists = 5,
    /// Unknown origin
    Unknown = 255,
}

impl Origin {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "crowdsec" => Origin::Crowdsec,
            "cscli" | "cscli-import" => Origin::Cscli,
            "capi" => Origin::Capi,
            "console" => Origin::Console,
            "lists" => Origin::Lists,
            _ => Origin::Unknown,
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Origin::Crowdsec,
            2 => Origin::Cscli,
            3 => Origin::Capi,
            4 => Origin::Console,
            5 => Origin::Lists,
            _ => Origin::Unknown,
        }
    }

    /// Short label for logs and ban templates (`{{origin}}`).
    pub fn as_str(self) -> &'static str {
        match self {
            Origin::Crowdsec => "crowdsec",
            Origin::Cscli => "cscli",
            Origin::Capi => "capi",
            Origin::Console => "console",
            Origin::Lists => "lists",
            Origin::Unknown => "unknown",
        }
    }
}

/// Scenario entry stored in the scenario table
/// Each unique scenario is stored once and referenced by ID
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShmScenario {
    /// Length of the scenario string (0 = empty slot)
    pub len: u8,
    /// Scenario string data (null-terminated for convenience)
    pub data: [u8; MAX_SCENARIO_LEN],
}

impl ShmScenario {
    pub const fn empty() -> Self {
        Self {
            len: 0,
            data: [0; MAX_SCENARIO_LEN],
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn matches(&self, scenario: &str) -> bool {
        if self.len as usize != scenario.len() {
            return false;
        }
        &self.data[..self.len as usize] == scenario.as_bytes()
    }

    pub fn from_str(scenario: &str) -> Self {
        let mut entry = Self::empty();
        let bytes = scenario.as_bytes();
        let len = bytes.len().min(MAX_SCENARIO_LEN);
        entry.len = len as u8;
        entry.data[..len].copy_from_slice(&bytes[..len]);
        entry
    }

    pub fn as_str(&self) -> &str {
        if self.len == 0 {
            return "";
        }
        std::str::from_utf8(&self.data[..self.len as usize]).unwrap_or("")
    }
}

/// Ban `reason` strings use the same packed representation as scenarios.
pub type ShmReason = ShmScenario;

/// Hash table entry for IP decisions
/// Stores both individual IPs and CIDR ranges in the same table
/// Supports multiple decision types per IP via bitmask
/// Size: 48 bytes (includes alignment padding for i64)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShmHashEntry {
    /// Cached hash value (0 = empty, 1 = tombstone, >1 = valid)
    pub hash: u32,
    /// Address family: 4 for IPv4, 6 for IPv6
    pub family: u8,
    /// Decision types bitmask (bit0=ban, bit1=captcha, bit2=throttle)
    /// Multiple types can be active simultaneously
    pub decision_types: u8,
    /// Origin of the decision (most recent)
    pub origin: u8,
    /// Flags: bit 0 = tombstone, bit 2 = is_cidr
    pub flags: u8,
    /// CIDR prefix length (32 for IPv4 single IP, 128 for IPv6 single IP)
    pub prefix_len: u8,
    /// Padding for alignment
    pub _pad: [u8; 3],
    /// IP address bytes (network address for CIDR)
    pub addr: [u8; 16],
    /// Expiration timestamp (seconds since epoch), 0 = no expiry
    /// This is the maximum expiry across all active decision types
    pub expires: i64,
    /// Scenario ID (index into scenario table), 0 = no scenario
    pub scenario_id: u16,
    /// Ban reason ID (index into reason table), 0 = no reason stored
    pub reason_id: u16,
}

impl ShmHashEntry {
    pub const fn empty() -> Self {
        Self {
            hash: HASH_EMPTY,
            family: 0,
            decision_types: 0,
            origin: 0,
            flags: 0,
            prefix_len: 0,
            _pad: [0; 3],
            addr: [0; 16],
            expires: 0,
            scenario_id: 0,
            reason_id: 0,
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.hash == HASH_EMPTY
    }

    #[inline]
    pub fn is_tombstone(&self) -> bool {
        self.hash == HASH_TOMBSTONE || (self.flags & FLAG_TOMBSTONE) != 0
    }

    #[inline]
    pub fn is_vacant(&self) -> bool {
        self.is_empty() || self.is_tombstone()
    }

    #[inline]
    pub fn is_cidr(&self) -> bool {
        (self.flags & FLAG_IS_CIDR) != 0
    }

    #[inline]
    pub fn mark_tombstone(&mut self) {
        self.hash = HASH_TOMBSTONE;
        self.flags |= FLAG_TOMBSTONE;
        self.decision_types = 0;
    }

    /// Check if this entry has any active decision types
    #[inline]
    pub fn has_decisions(&self) -> bool {
        self.decision_types != 0
    }

    /// Add a decision type to the bitmask
    #[inline]
    pub fn add_decision_type(&mut self, dt: DecisionType) {
        self.decision_types |= dt.to_bit();
    }

    /// Remove a decision type from the bitmask
    #[inline]
    pub fn remove_decision_type(&mut self, dt: DecisionType) {
        self.decision_types &= !dt.to_bit();
    }

    /// Check if a specific decision type is active
    #[inline]
    pub fn has_decision_type(&self, dt: DecisionType) -> bool {
        self.decision_types & dt.to_bit() != 0
    }

    /// Check if this entry matches an exact IP (not CIDR)
    pub fn matches_ip(&self, ip: &IpAddr) -> bool {
        if self.is_vacant() {
            return false;
        }
        match ip {
            IpAddr::V4(v4) => self.family == 4 && !self.is_cidr() && self.addr[..4] == v4.octets(),
            IpAddr::V6(v6) => self.family == 6 && !self.is_cidr() && self.addr == v6.octets(),
        }
    }

    /// Check if this entry matches a CIDR key (network + prefix)
    pub fn matches_cidr(&self, family: u8, prefix_len: u8, network: &[u8]) -> bool {
        if self.is_vacant() || !self.is_cidr() {
            return false;
        }
        if self.family != family || self.prefix_len != prefix_len {
            return false;
        }
        let len = if family == 4 { 4 } else { 16 };
        self.addr[..len] == network[..len]
    }

    /// Get the highest priority decision type from the bitmask
    pub fn decision_type(&self) -> DecisionType {
        DecisionType::from_bitmask(self.decision_types)
    }

    /// Get the raw decision types bitmask
    pub fn decision_types_mask(&self) -> u8 {
        self.decision_types
    }

    pub fn origin(&self) -> Origin {
        Origin::from_u8(self.origin)
    }

    pub fn is_expired_at(&self, now: i64) -> bool {
        if self.expires == 0 {
            return false; // No expiry
        }
        now > self.expires
    }
}

/// Decision metadata for adding entries
pub struct DecisionInfo<'a> {
    pub ip: &'a IpAddr,
    pub decision_type: DecisionType,
    pub origin: Origin,
    pub scenario: Option<&'a str>,
    pub reason: Option<&'a str>,
    pub duration_secs: Option<i64>,
}

/// CIDR decision metadata
pub struct CidrDecisionInfo<'a> {
    pub network: &'a [u8],
    pub family: u8,
    pub prefix_len: u8,
    pub decision_type: DecisionType,
    pub origin: Origin,
    pub scenario: Option<&'a str>,
    pub reason: Option<&'a str>,
    pub duration_secs: Option<i64>,
}

/// Shared memory data header
#[repr(C)]
pub struct ShmData {
    pub magic: u32,
    pub layout_version: u32,
    /// Read-write lock for synchronization
    pub lock: ngx_atomic_t,
    /// Atomic flag for poller election (0 = no poller, pid of poller worker)
    pub poller_pid: ngx_atomic_t,
    /// Number of active entries (individual IPs + CIDRs)
    pub count: u32,
    /// Hash table capacity (number of slots)
    pub capacity: u32,
    /// Number of scenarios in the table
    pub scenario_count: u16,
    /// Number of ban-reason strings in the table
    pub reason_count: u16,
    /// Version counter (incremented on updates)
    pub version: u64,
    /// Clock hand for LRU eviction
    pub clock_hand: u32,
    /// Number of evictions performed (for monitoring)
    pub eviction_count: u32,
    /// Byte offset from this header to the hash table entries.
    entries_offset: usize,
    /// Byte offset from this header to the scenario table.
    scenarios_offset: usize,
    /// Byte offset from this header to the deduplicated ban-reason table.
    reasons_offset: usize,
    /// Prefix lengths that have been seen. Stale bits are harmless and avoid
    /// maintaining counters on the update path.
    cidr_prefixes: [u64; 3],
}

/// Global pointer to the shared memory zone
static SHM_ZONE: AtomicPtr<ngx_shm_zone_t> = AtomicPtr::new(ptr::null_mut());

/// Prometheus-style counters in a tiny separate zone (does not change `ShmData` layout).
#[repr(C)]
pub struct MetricsShm {
    pub http_lookups: AtomicU64,
    pub http_bans: AtomicU64,
    pub http_captcha: AtomicU64,
    pub http_bypass: AtomicU64,
    pub lapi_poll_ok: AtomicU64,
    pub lapi_poll_err: AtomicU64,
    /// Unix seconds when the stream poller last completed a successful LAPI poll (`0` = never).
    pub lapi_last_success_unix_secs: AtomicU64,
}

static METRICS_SHM_ZONE: AtomicPtr<ngx_shm_zone_t> = AtomicPtr::new(ptr::null_mut());

/// Local cache of whether this worker is the poller (avoid repeated shm access)
static IS_POLLER: AtomicBool = AtomicBool::new(false);

/// FNV-1a hash function for IP addresses
/// Returns hash value >= 2 (0 and 1 are reserved for empty/tombstone)
#[inline]
fn hash_ip(ip: &IpAddr) -> u32 {
    const FNV_OFFSET: u32 = 2166136261;
    const FNV_PRIME: u32 = 16777619;

    let mut hash = FNV_OFFSET;

    match ip {
        IpAddr::V4(v4) => {
            hash ^= 4u32; // family marker
            for byte in v4.octets() {
                hash ^= byte as u32;
                hash = hash.wrapping_mul(FNV_PRIME);
            }
        }
        IpAddr::V6(v6) => {
            hash ^= 6u32; // family marker
            for byte in v6.octets() {
                hash ^= byte as u32;
                hash = hash.wrapping_mul(FNV_PRIME);
            }
        }
    }

    // Ensure hash is >= 2 (0 = empty, 1 = tombstone)
    if hash < 2 { hash + 2 } else { hash }
}

/// Hash function for CIDR entries (network address + prefix length)
#[inline]
fn hash_cidr(family: u8, prefix_len: u8, network: &[u8]) -> u32 {
    const FNV_OFFSET: u32 = 2166136261;
    const FNV_PRIME: u32 = 16777619;

    let mut hash = FNV_OFFSET;

    // Include family and prefix in hash
    hash ^= family as u32;
    hash = hash.wrapping_mul(FNV_PRIME);
    hash ^= prefix_len as u32;
    hash = hash.wrapping_mul(FNV_PRIME);

    // Hash network bytes
    let len = if family == 4 { 4 } else { 16 };
    for i in 0..len {
        hash ^= network[i] as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    if hash < 2 { hash + 2 } else { hash }
}

/// Apply netmask to IPv4 address, returning network address
#[inline]
fn apply_ipv4_mask(addr: &[u8; 4], prefix_len: u8) -> [u8; 4] {
    if prefix_len == 0 {
        return [0; 4];
    }
    if prefix_len >= 32 {
        return *addr;
    }

    let mask = !((1u32 << (32 - prefix_len)) - 1);
    let ip = u32::from_be_bytes(*addr);
    let network = ip & mask;
    network.to_be_bytes()
}

/// Apply netmask to IPv6 address, returning network address
#[inline]
fn apply_ipv6_mask(addr: &[u8; 16], prefix_len: u8) -> [u8; 16] {
    if prefix_len == 0 {
        return [0; 16];
    }
    if prefix_len >= 128 {
        return *addr;
    }

    let mut result = [0u8; 16];
    let full_bytes = (prefix_len / 8) as usize;
    let remaining_bits = prefix_len % 8;

    // Copy full bytes
    result[..full_bytes].copy_from_slice(&addr[..full_bytes]);

    // Handle partial byte
    if remaining_bits > 0 && full_bytes < 16 {
        let mask = !((1u8 << (8 - remaining_bits)) - 1);
        result[full_bytes] = addr[full_bytes] & mask;
    }

    result
}

/// Initialize shared memory zone
/// Called from postconfiguration
///
/// # Safety
/// Must be called with valid NGINX configuration context
pub unsafe fn init_shm_zone(
    cf: *mut ngx::ffi::ngx_conf_t,
    name: &ngx_str_t,
    size: usize,
) -> Result<*mut ngx_shm_zone_t, ()> {
    unsafe {
        let shm_zone = ngx::ffi::ngx_shared_memory_add(
            cf,
            name as *const _ as *mut _,
            size,
            &raw const crate::ngx_http_crowdsec_module as *mut _,
        );

        if shm_zone.is_null() {
            return Err(());
        }

        // Set the init callback
        (*shm_zone).init = Some(shm_zone_init);
        (*shm_zone).data = ptr::null_mut();

        // Store globally for access from handlers
        SHM_ZONE.store(shm_zone, Ordering::SeqCst);

        Ok(shm_zone)
    }
}

/// True if `data` points to a [`ShmData`] header written by this module layout.
#[inline]
unsafe fn decision_shm_layout_matches(data: *mut std::ffi::c_void) -> bool {
    let hdr = data.cast::<ShmData>();
    (*hdr).magic == SHM_MAGIC && (*hdr).layout_version == SHM_LAYOUT_VERSION
}

/// Shared memory zone initialization callback
/// Called by NGINX after the zone is allocated
unsafe extern "C" fn shm_zone_init(
    shm_zone: *mut ngx_shm_zone_t,
    data: *mut std::ffi::c_void,
) -> ngx_int_t {
    unsafe {
        if !data.is_null() {
            if decision_shm_layout_matches(data) {
                (*shm_zone).data = data;
                // The previous generation's poller exits after new workers start. Reset
                // its claim now so one of the new workers can take over immediately.
                let shm_data = data as *mut ShmData;
                let poller_atomic = &*((&(*shm_data).poller_pid) as *const ngx_atomic_t
                    as *const std::sync::atomic::AtomicIsize);
                poller_atomic.store(0, Ordering::SeqCst);
                return NGX_OK as ngx_int_t;
            }
            eprintln!(
                "crowdsec: decision shared memory is incompatible with this module (layout changed). \
                 Perform a full nginx restart after upgrading the module, not only `reload`."
            );
            return ngx::ffi::NGX_ERROR as ngx_int_t;
        }

        let shpool = (*shm_zone).shm.addr as *mut ngx_slab_pool_t;
        if shpool.is_null() {
            return ngx::ffi::NGX_ERROR as ngx_int_t;
        }

        // Calculate capacity based on zone size
        let entry_size = std::mem::size_of::<ShmHashEntry>();
        let scenario_size = std::mem::size_of::<ShmScenario>();
        let header_size = std::mem::size_of::<ShmData>();

        // Reserve memory for header and two string tables (scenarios + ban reasons)
        let string_table_bytes = scenario_size * MAX_SCENARIOS;
        let fixed_overhead = header_size + string_table_bytes * 2;

        // Use remaining memory for hash table (with safety margin for slab allocator overhead)
        let available_for_entries =
            (*shm_zone).shm.size.saturating_sub(fixed_overhead) * USABLE_MEMORY_PERCENT / 100;

        // Capacity is simply how many entries fit in available memory
        let capacity = (available_for_entries / entry_size).max(MIN_CAPACITY as usize) as u32;

        eprintln!(
            "crowdsec: initializing shared memory - zone size: {} bytes, hash capacity: {} entries",
            (*shm_zone).shm.size,
            capacity
        );

        // Allocate header
        let header_ptr = ngx_slab_alloc_locked(shpool, header_size);
        if header_ptr.is_null() {
            eprintln!("crowdsec: failed to allocate SHM header");
            return ngx::ffi::NGX_ERROR as ngx_int_t;
        }

        // Allocate hash table
        let entries_size = entry_size * capacity as usize;
        let entries_ptr = ngx_slab_alloc_locked(shpool, entries_size);
        if entries_ptr.is_null() {
            eprintln!(
                "crowdsec: failed to allocate SHM hash table ({} bytes)",
                entries_size
            );
            return ngx::ffi::NGX_ERROR as ngx_int_t;
        }

        // Allocate scenario table
        let scenarios_size = scenario_size * MAX_SCENARIOS;
        let scenarios_ptr = ngx_slab_alloc_locked(shpool, scenarios_size);
        if scenarios_ptr.is_null() {
            eprintln!("crowdsec: failed to allocate SHM scenario table");
            return ngx::ffi::NGX_ERROR as ngx_int_t;
        }

        // Allocate ban-reason table (same row size as scenarios)
        let reasons_size = scenario_size * MAX_SCENARIOS;
        let reasons_ptr = ngx_slab_alloc_locked(shpool, reasons_size);
        if reasons_ptr.is_null() {
            eprintln!("crowdsec: failed to allocate SHM reason table");
            return ngx::ffi::NGX_ERROR as ngx_int_t;
        }

        // Initialize the data structure
        let shm_data = header_ptr as *mut ShmData;
        (*shm_data).magic = SHM_MAGIC;
        (*shm_data).layout_version = SHM_LAYOUT_VERSION;
        (*shm_data).lock = 0;
        (*shm_data).poller_pid = 0;
        (*shm_data).count = 0;
        (*shm_data).capacity = capacity;
        (*shm_data).scenario_count = 0;
        (*shm_data).reason_count = 0;
        (*shm_data).version = 0;
        (*shm_data).clock_hand = 0;
        (*shm_data).eviction_count = 0;
        (*shm_data).entries_offset = (entries_ptr as usize).wrapping_sub(header_ptr as usize);
        (*shm_data).scenarios_offset = (scenarios_ptr as usize).wrapping_sub(header_ptr as usize);
        (*shm_data).reasons_offset = (reasons_ptr as usize).wrapping_sub(header_ptr as usize);
        (*shm_data).cidr_prefixes = [0; 3];

        // Zero out entries and string tables
        ptr::write_bytes(entries_ptr as *mut ShmHashEntry, 0, capacity as usize);
        ptr::write_bytes(scenarios_ptr as *mut ShmScenario, 0, MAX_SCENARIOS);
        ptr::write_bytes(reasons_ptr as *mut ShmReason, 0, MAX_SCENARIOS);

        (*shm_zone).data = header_ptr;

        NGX_OK as ngx_int_t
    }
}

/// Get the shared memory data pointer
fn get_shm_data() -> Option<*mut ShmData> {
    let zone = SHM_ZONE.load(Ordering::SeqCst);
    if zone.is_null() {
        return None;
    }
    unsafe {
        let data = (*zone).data as *mut ShmData;
        if data.is_null() { None } else { Some(data) }
    }
}

/// Get entries array from shared memory data
#[inline]
unsafe fn get_entries(shm_data: *mut ShmData) -> *mut ShmHashEntry {
    unsafe { (shm_data as usize).wrapping_add((*shm_data).entries_offset) as *mut ShmHashEntry }
}

/// Get scenarios array from shared memory data
#[inline]
unsafe fn get_scenarios(shm_data: *mut ShmData) -> *mut ShmScenario {
    unsafe { (shm_data as usize).wrapping_add((*shm_data).scenarios_offset) as *mut ShmScenario }
}

#[inline]
unsafe fn prefix_is_present(shm_data: *mut ShmData, prefix: u8) -> bool {
    unsafe {
        let prefix = prefix as usize;
        ((*shm_data).cidr_prefixes[prefix / 64] & (1u64 << (prefix % 64))) != 0
    }
}

#[inline]
unsafe fn mark_prefix_present(shm_data: *mut ShmData, prefix: u8) {
    unsafe {
        let prefix = prefix as usize;
        (*shm_data).cidr_prefixes[prefix / 64] |= 1u64 << (prefix % 64);
    }
}

/// Get ban-reason strings array from shared memory data
#[inline]
unsafe fn get_reasons(shm_data: *mut ShmData) -> *mut ShmReason {
    unsafe { (shm_data as usize).wrapping_add((*shm_data).reasons_offset) as *mut ShmReason }
}

/// Find or create a scenario ID for the given scenario string
/// Must be called with write lock held
/// Returns scenario_id (1-based), or 0 if table is full
unsafe fn get_or_create_scenario_id(shm_data: *mut ShmData, scenario: &str) -> u16 {
    unsafe {
        let scenarios = get_scenarios(shm_data);
        let count = (*shm_data).scenario_count as usize;

        // Search existing scenarios
        for i in 0..count {
            let entry = &*scenarios.add(i);
            if entry.matches(scenario) {
                return (i + 1) as u16; // 1-based ID
            }
        }

        // Not found, add new if space available
        if count < MAX_SCENARIOS {
            let entry = &mut *scenarios.add(count);
            *entry = ShmScenario::from_str(scenario);
            (*shm_data).scenario_count += 1;
            return (count + 1) as u16; // 1-based ID
        }

        // Table full
        0
    }
}

/// Get scenario string by ID
/// Returns None if ID is invalid or 0
pub fn get_scenario(scenario_id: u16) -> Option<String> {
    if scenario_id == 0 {
        return None;
    }

    let shm_data = get_shm_data()?;

    unsafe {
        ngx_rwlock_rlock(&mut (*shm_data).lock);

        let result = if (scenario_id as usize) <= (*shm_data).scenario_count as usize {
            let scenarios = get_scenarios(shm_data);
            let entry = &*scenarios.add(scenario_id as usize - 1);
            Some(entry.as_str().to_string())
        } else {
            None
        };

        ngx_rwlock_unlock(&mut (*shm_data).lock);
        result
    }
}

/// Find or create a reason ID for the given ban reason string.
/// Must be called with write lock held. Returns 1-based ID, or 0 if the table is full.
unsafe fn get_or_create_reason_id(shm_data: *mut ShmData, reason: &str) -> u16 {
    let reasons = get_reasons(shm_data);
    let count = (*shm_data).reason_count as usize;

    for i in 0..count {
        let entry = &*reasons.add(i);
        if entry.matches(reason) {
            return (i + 1) as u16;
        }
    }

    if count < MAX_SCENARIOS {
        let entry = &mut *reasons.add(count);
        *entry = ShmScenario::from_str(reason);
        (*shm_data).reason_count += 1;
        return (count + 1) as u16;
    }

    0
}

/// Get ban reason text by ID (`0` = none).
pub fn get_reason(reason_id: u16) -> Option<String> {
    if reason_id == 0 {
        return None;
    }

    let shm_data = get_shm_data()?;

    unsafe {
        ngx_rwlock_rlock(&mut (*shm_data).lock);

        let result = if (reason_id as usize) <= (*shm_data).reason_count as usize {
            let reasons = get_reasons(shm_data);
            let entry = &*reasons.add(reason_id as usize - 1);
            Some(entry.as_str().to_string())
        } else {
            None
        };

        ngx_rwlock_unlock(&mut (*shm_data).lock);
        result
    }
}

/// Result of looking up an IP in shared memory
pub struct LookupResult {
    pub found: bool,
    pub decision_type: DecisionType,
    pub origin: Origin,
    pub scenario_id: u16,
    pub reason_id: u16,
}

/// Find entry by hash using linear probing
/// Returns (slot_index, found) where found indicates if the entry matches
#[inline]
unsafe fn find_slot_ip(
    entries: *mut ShmHashEntry,
    capacity: u32,
    hash: u32,
    ip: &IpAddr,
) -> (u32, bool) {
    unsafe {
        let mut idx = hash % capacity;
        let start_idx = idx;

        loop {
            let entry = &*entries.add(idx as usize);

            if entry.is_empty() {
                // Empty slot - entry not found
                return (idx, false);
            }

            if !entry.is_tombstone() && entry.hash == hash && entry.matches_ip(ip) {
                // Found matching entry
                return (idx, true);
            }

            // Linear probe to next slot
            idx = (idx + 1) % capacity;
            if idx == start_idx {
                // Wrapped around - table is full
                return (idx, false);
            }
        }
    }
}

/// Find entry by CIDR key using linear probing
#[inline]
unsafe fn find_slot_cidr(
    entries: *mut ShmHashEntry,
    capacity: u32,
    hash: u32,
    family: u8,
    prefix_len: u8,
    network: &[u8],
) -> (u32, bool) {
    unsafe {
        let mut idx = hash % capacity;
        let start_idx = idx;

        loop {
            let entry = &*entries.add(idx as usize);

            if entry.is_empty() {
                return (idx, false);
            }

            if !entry.is_tombstone()
                && entry.hash == hash
                && entry.matches_cidr(family, prefix_len, network)
            {
                return (idx, true);
            }

            idx = (idx + 1) % capacity;
            if idx == start_idx {
                return (idx, false);
            }
        }
    }
}

/// Find first vacant slot (empty or tombstone) for insertion
#[inline]
unsafe fn find_vacant_slot(entries: *mut ShmHashEntry, capacity: u32, hash: u32) -> Option<u32> {
    unsafe {
        let mut idx = hash % capacity;
        let start_idx = idx;

        loop {
            let entry = &*entries.add(idx as usize);

            if entry.is_vacant() {
                return Some(idx);
            }

            idx = (idx + 1) % capacity;
            if idx == start_idx {
                return None; // Table is full
            }
        }
    }
}

/// Evict an entry in round-robin order.
/// ponytail: upgrade to sampled eviction only if full-zone churn is measured.
/// Must be called with write lock held
/// Returns the index of the evicted slot
unsafe fn evict_clock(shm_data: *mut ShmData) -> Option<u32> {
    unsafe {
        let entries = get_entries(shm_data);
        let capacity = (*shm_data).capacity;
        let mut hand = (*shm_data).clock_hand;
        let start = hand;

        loop {
            let entry = &mut *entries.add(hand as usize);

            if !entry.is_vacant() {
                entry.mark_tombstone();
                (*shm_data).count = (*shm_data).count.saturating_sub(1);
                (*shm_data).eviction_count += 1;
                (*shm_data).clock_hand = (hand + 1) % capacity;
                return Some(hand);
            }

            hand = (hand + 1) % capacity;
            if hand == start {
                break;
            }
        }

        None
    }
}

/// Check if an IP has a decision and return details
/// This performs a hierarchical lookup:
/// 1. Check exact IP match first (O(1) hash lookup)
/// 2. Then check CIDR ranges from most specific to least specific
pub fn lookup_ip(ip: &IpAddr) -> LookupResult {
    let shm_data = match get_shm_data() {
        Some(data) => data,
        None => {
            return LookupResult {
                found: false,
                decision_type: DecisionType::Unknown,
                origin: Origin::Unknown,
                scenario_id: 0,
                reason_id: 0,
            };
        }
    };

    unsafe {
        ngx_rwlock_rlock(&mut (*shm_data).lock);

        let entries = get_entries(shm_data);
        let capacity = (*shm_data).capacity;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        // 1. Check exact IP match first
        let hash = hash_ip(ip);
        let (idx, found) = find_slot_ip(entries, capacity, hash, ip);

        if found {
            let entry = &*entries.add(idx as usize);
            if !entry.is_expired_at(now) {
                let result = LookupResult {
                    found: true,
                    decision_type: entry.decision_type(),
                    origin: entry.origin(),
                    scenario_id: entry.scenario_id,
                    reason_id: entry.reason_id,
                };
                ngx_rwlock_unlock(&mut (*shm_data).lock);
                return result;
            }
        }

        // 2. Check CIDR ranges from most specific to least specific
        let result = match ip {
            IpAddr::V4(v4) => lookup_cidr_v4(shm_data, entries, capacity, &v4.octets(), now),
            IpAddr::V6(v6) => lookup_cidr_v6(shm_data, entries, capacity, &v6.octets(), now),
        };

        ngx_rwlock_unlock(&mut (*shm_data).lock);
        result
    }
}

/// Lookup IPv4 address in CIDR entries (most specific to least specific)
/// Must be called with read lock held
unsafe fn lookup_cidr_v4(
    shm_data: *mut ShmData,
    entries: *mut ShmHashEntry,
    capacity: u32,
    addr: &[u8; 4],
    now: i64,
) -> LookupResult {
    unsafe {
        for prefix_len in (0..=32).rev() {
            if !prefix_is_present(shm_data, prefix_len) {
                continue;
            }
            let network = apply_ipv4_mask(addr, prefix_len);
            let hash = hash_cidr(4, prefix_len, &network);
            let (idx, found) = find_slot_cidr(entries, capacity, hash, 4, prefix_len, &network);

            if found {
                let entry = &*entries.add(idx as usize);
                if !entry.is_expired_at(now) {
                    return LookupResult {
                        found: true,
                        decision_type: entry.decision_type(),
                        origin: entry.origin(),
                        scenario_id: entry.scenario_id,
                        reason_id: entry.reason_id,
                    };
                }
            }
        }

        LookupResult {
            found: false,
            decision_type: DecisionType::Unknown,
            origin: Origin::Unknown,
            scenario_id: 0,
            reason_id: 0,
        }
    }
}

/// Lookup IPv6 address in CIDR entries (most specific to least specific)
/// Must be called with read lock held
unsafe fn lookup_cidr_v6(
    shm_data: *mut ShmData,
    entries: *mut ShmHashEntry,
    capacity: u32,
    addr: &[u8; 16],
    now: i64,
) -> LookupResult {
    unsafe {
        for prefix_len in (0..=128).rev() {
            if !prefix_is_present(shm_data, prefix_len) {
                continue;
            }
            let network = apply_ipv6_mask(addr, prefix_len);
            let hash = hash_cidr(6, prefix_len, &network);
            let (idx, found) = find_slot_cidr(entries, capacity, hash, 6, prefix_len, &network);

            if found {
                let entry = &*entries.add(idx as usize);
                if !entry.is_expired_at(now) {
                    return LookupResult {
                        found: true,
                        decision_type: entry.decision_type(),
                        origin: entry.origin(),
                        scenario_id: entry.scenario_id,
                        reason_id: entry.reason_id,
                    };
                }
            }
        }

        LookupResult {
            found: false,
            decision_type: DecisionType::Unknown,
            origin: Origin::Unknown,
            scenario_id: 0,
            reason_id: 0,
        }
    }
}

/// Check if an IP is banned (convenience wrapper for lookup_ip)
pub fn is_banned(ip: &IpAddr) -> bool {
    lookup_ip(ip).found
}

/// Add a decision for an individual IP to shared memory
/// If the IP already has decisions, the new decision type is added to the bitmask
/// and the expiry is extended if the new one is longer
pub fn add_decision(info: &DecisionInfo) {
    let shm_data = match get_shm_data() {
        Some(data) => data,
        None => return,
    };

    let expires = info
        .duration_secs
        .map(|d| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|t| t.as_secs() as i64 + d)
                .unwrap_or(0)
        })
        .unwrap_or(0);

    unsafe {
        ngx_rwlock_wlock(&mut (*shm_data).lock);
        // Get or create scenario ID
        let scenario_id = info
            .scenario
            .map(|s| get_or_create_scenario_id(shm_data, s))
            .unwrap_or(0);

        let reason_id = info
            .reason
            .map(|r| get_or_create_reason_id(shm_data, r))
            .unwrap_or(0);

        let hash = hash_ip(info.ip);
        let decision_bit = info.decision_type.to_bit();

        let entries = get_entries(shm_data);
        let capacity = (*shm_data).capacity;

        // Check if already exists
        let (idx, found) = find_slot_ip(entries, capacity, hash, info.ip);

        if found {
            // Merge with existing entry - add decision type to bitmask
            let entry = &mut *entries.add(idx as usize);
            entry.decision_types |= decision_bit;
            entry.origin = info.origin as u8;
            // Keep the longer expiry
            if expires > entry.expires {
                entry.expires = expires;
            }
            // Update scenario if provided
            if scenario_id != 0 {
                entry.scenario_id = scenario_id;
            }
            if reason_id != 0 {
                entry.reason_id = reason_id;
            }
            (*shm_data).version += 1;
            ngx_rwlock_unlock(&mut (*shm_data).lock);
            return;
        }

        // Build new entry
        let mut new_entry = ShmHashEntry::empty();
        new_entry.hash = hash;
        new_entry.decision_types = decision_bit;
        new_entry.origin = info.origin as u8;
        new_entry.expires = expires;
        new_entry.scenario_id = scenario_id;
        new_entry.reason_id = reason_id;
        new_entry.flags = 0;

        match info.ip {
            IpAddr::V4(v4) => {
                new_entry.family = 4;
                new_entry.prefix_len = 32;
                new_entry.addr[..4].copy_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                new_entry.family = 6;
                new_entry.prefix_len = 128;
                new_entry.addr.copy_from_slice(&v6.octets());
            }
        }

        // Find vacant slot for insertion
        let slot = match find_vacant_slot(entries, capacity, hash) {
            Some(s) => s,
            None => {
                // Table is full, try to evict
                match evict_clock(shm_data) {
                    Some(evicted) => evicted,
                    None => {
                        eprintln!("crowdsec: hash table full, cannot add entry");
                        ngx_rwlock_unlock(&mut (*shm_data).lock);
                        return;
                    }
                }
            }
        };

        // Insert the new entry
        let entry = &mut *entries.add(slot as usize);
        *entry = new_entry;
        (*shm_data).count += 1;
        (*shm_data).version += 1;

        ngx_rwlock_unlock(&mut (*shm_data).lock);
    }
}

/// Add a CIDR range decision to shared memory
/// If the CIDR already has decisions, the new decision type is added to the bitmask
pub fn add_cidr_decision(info: &CidrDecisionInfo) {
    let shm_data = match get_shm_data() {
        Some(data) => data,
        None => return,
    };

    let expires = info
        .duration_secs
        .map(|d| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|t| t.as_secs() as i64 + d)
                .unwrap_or(0)
        })
        .unwrap_or(0);

    unsafe {
        ngx_rwlock_wlock(&mut (*shm_data).lock);
        mark_prefix_present(shm_data, info.prefix_len);

        // Get or create scenario ID
        let scenario_id = info
            .scenario
            .map(|s| get_or_create_scenario_id(shm_data, s))
            .unwrap_or(0);

        let reason_id = info
            .reason
            .map(|r| get_or_create_reason_id(shm_data, r))
            .unwrap_or(0);

        let hash = hash_cidr(info.family, info.prefix_len, info.network);
        let decision_bit = info.decision_type.to_bit();

        let entries = get_entries(shm_data);
        let capacity = (*shm_data).capacity;

        // Check if already exists
        let (idx, found) = find_slot_cidr(
            entries,
            capacity,
            hash,
            info.family,
            info.prefix_len,
            info.network,
        );

        if found {
            // Merge with existing entry - add decision type to bitmask
            let entry = &mut *entries.add(idx as usize);
            entry.decision_types |= decision_bit;
            entry.origin = info.origin as u8;
            if expires > entry.expires {
                entry.expires = expires;
            }
            if scenario_id != 0 {
                entry.scenario_id = scenario_id;
            }
            if reason_id != 0 {
                entry.reason_id = reason_id;
            }
            (*shm_data).version += 1;
            ngx_rwlock_unlock(&mut (*shm_data).lock);
            return;
        }

        // Build new entry
        let mut new_entry = ShmHashEntry::empty();
        new_entry.hash = hash;
        new_entry.family = info.family;
        new_entry.prefix_len = info.prefix_len;
        new_entry.decision_types = decision_bit;
        new_entry.origin = info.origin as u8;
        new_entry.expires = expires;
        new_entry.scenario_id = scenario_id;
        new_entry.reason_id = reason_id;
        new_entry.flags = FLAG_IS_CIDR;

        let len = if info.family == 4 { 4 } else { 16 };
        new_entry.addr[..len].copy_from_slice(&info.network[..len]);

        // Find vacant slot
        let slot = match find_vacant_slot(entries, capacity, hash) {
            Some(s) => s,
            None => match evict_clock(shm_data) {
                Some(evicted) => evicted,
                None => {
                    eprintln!("crowdsec: hash table full, cannot add CIDR entry");
                    ngx_rwlock_unlock(&mut (*shm_data).lock);
                    return;
                }
            },
        };

        let entry = &mut *entries.add(slot as usize);
        *entry = new_entry;
        (*shm_data).count += 1;
        (*shm_data).version += 1;

        ngx_rwlock_unlock(&mut (*shm_data).lock);
    }
}

/// Add a banned IP to shared memory (legacy compatibility wrapper)
pub fn add_ban(ip: &IpAddr, duration_secs: Option<i64>) {
    add_decision(&DecisionInfo {
        ip,
        decision_type: DecisionType::Ban,
        origin: Origin::Unknown,
        scenario: None,
        reason: None,
        duration_secs,
    });
}

/// Remove a specific decision type for an IP from shared memory
/// Only removes the entry entirely if no decision types remain
pub fn remove_decision_type(ip: &IpAddr, decision_type: DecisionType) {
    let shm_data = match get_shm_data() {
        Some(data) => data,
        None => return,
    };

    unsafe {
        ngx_rwlock_wlock(&mut (*shm_data).lock);

        let entries = get_entries(shm_data);
        let capacity = (*shm_data).capacity;
        let hash = hash_ip(ip);

        let (idx, found) = find_slot_ip(entries, capacity, hash, ip);

        if found {
            let entry = &mut *entries.add(idx as usize);
            entry.remove_decision_type(decision_type);

            // Only tombstone if no decision types remain
            if !entry.has_decisions() {
                entry.mark_tombstone();
                (*shm_data).count = (*shm_data).count.saturating_sub(1);
            }
            (*shm_data).version += 1;
        }

        ngx_rwlock_unlock(&mut (*shm_data).lock);
    }
}

/// Remove a decision for an IP from shared memory (removes all decision types)
pub fn remove_decision(ip: &IpAddr) {
    let shm_data = match get_shm_data() {
        Some(data) => data,
        None => return,
    };

    unsafe {
        ngx_rwlock_wlock(&mut (*shm_data).lock);

        let entries = get_entries(shm_data);
        let capacity = (*shm_data).capacity;
        let hash = hash_ip(ip);

        let (idx, found) = find_slot_ip(entries, capacity, hash, ip);

        if found {
            let entry = &mut *entries.add(idx as usize);
            entry.mark_tombstone();
            (*shm_data).count = (*shm_data).count.saturating_sub(1);
            (*shm_data).version += 1;
        }

        ngx_rwlock_unlock(&mut (*shm_data).lock);
    }
}

/// Remove a specific decision type for a CIDR range from shared memory
pub fn remove_cidr_decision_type(
    family: u8,
    prefix_len: u8,
    network: &[u8],
    decision_type: DecisionType,
) {
    let shm_data = match get_shm_data() {
        Some(data) => data,
        None => return,
    };

    unsafe {
        ngx_rwlock_wlock(&mut (*shm_data).lock);

        let entries = get_entries(shm_data);
        let capacity = (*shm_data).capacity;
        let hash = hash_cidr(family, prefix_len, network);

        let (idx, found) = find_slot_cidr(entries, capacity, hash, family, prefix_len, network);

        if found {
            let entry = &mut *entries.add(idx as usize);
            entry.remove_decision_type(decision_type);

            if !entry.has_decisions() {
                entry.mark_tombstone();
                (*shm_data).count = (*shm_data).count.saturating_sub(1);
            }
            (*shm_data).version += 1;
        }

        ngx_rwlock_unlock(&mut (*shm_data).lock);
    }
}

/// Remove a CIDR range decision from shared memory (removes all decision types)
pub fn remove_cidr_decision(family: u8, prefix_len: u8, network: &[u8]) {
    let shm_data = match get_shm_data() {
        Some(data) => data,
        None => return,
    };

    unsafe {
        ngx_rwlock_wlock(&mut (*shm_data).lock);

        let entries = get_entries(shm_data);
        let capacity = (*shm_data).capacity;
        let hash = hash_cidr(family, prefix_len, network);

        let (idx, found) = find_slot_cidr(entries, capacity, hash, family, prefix_len, network);

        if found {
            let entry = &mut *entries.add(idx as usize);
            entry.mark_tombstone();
            (*shm_data).count = (*shm_data).count.saturating_sub(1);
            (*shm_data).version += 1;
        }

        ngx_rwlock_unlock(&mut (*shm_data).lock);
    }
}

/// Remove a banned IP from shared memory (legacy compatibility wrapper)
pub fn remove_ban(ip: &IpAddr) {
    remove_decision(ip);
}

/// Clear all entries from shared memory
pub fn clear_all() {
    let shm_data = match get_shm_data() {
        Some(data) => data,
        None => return,
    };

    unsafe {
        ngx_rwlock_wlock(&mut (*shm_data).lock);

        let entries = get_entries(shm_data);
        let capacity = (*shm_data).capacity as usize;

        ptr::write_bytes(entries, 0, capacity);
        (*shm_data).count = 0;
        (*shm_data).clock_hand = 0;
        (*shm_data).version += 1;

        // Note: we don't clear scenarios as they may be reused

        ngx_rwlock_unlock(&mut (*shm_data).lock);
    }
}

/// Get current count of entries (IPs + CIDRs)
pub fn get_count() -> u32 {
    let shm_data = match get_shm_data() {
        Some(data) => data,
        None => return 0,
    };

    unsafe {
        ngx_rwlock_rlock(&mut (*shm_data).lock);
        let count = (*shm_data).count;
        ngx_rwlock_unlock(&mut (*shm_data).lock);
        count
    }
}

/// Get hash table capacity
pub fn get_capacity() -> u32 {
    let shm_data = match get_shm_data() {
        Some(data) => data,
        None => return 0,
    };

    unsafe {
        ngx_rwlock_rlock(&mut (*shm_data).lock);
        let capacity = (*shm_data).capacity;
        ngx_rwlock_unlock(&mut (*shm_data).lock);
        capacity
    }
}

/// Get eviction count (for monitoring)
pub fn get_eviction_count() -> u32 {
    let shm_data = match get_shm_data() {
        Some(data) => data,
        None => return 0,
    };

    unsafe {
        ngx_rwlock_rlock(&mut (*shm_data).lock);
        let count = (*shm_data).eviction_count;
        ngx_rwlock_unlock(&mut (*shm_data).lock);
        count
    }
}

/// Try to claim the poller role for this worker process
/// Returns true if this worker successfully became the poller
pub fn try_become_poller() -> bool {
    let shm_data = match get_shm_data() {
        Some(data) => data,
        None => return false,
    };

    let my_pid = std::process::id() as isize;

    unsafe {
        // Cast the poller_pid field to an atomic for CAS operation
        let poller_atomic = &*((&(*shm_data).poller_pid) as *const ngx_atomic_t
            as *const std::sync::atomic::AtomicIsize);

        // Try to claim: only succeed if currently 0
        match poller_atomic.compare_exchange(0, my_pid, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => {
                IS_POLLER.store(true, Ordering::SeqCst);
                true
            }
            Err(_) => false,
        }
    }
}

/// Check if this worker is the designated poller
pub fn is_poller() -> bool {
    IS_POLLER.load(Ordering::SeqCst)
}

/// Release this worker's poller claim without clearing a newer worker's claim.
pub fn release_poller() {
    let shm_data = match get_shm_data() {
        Some(data) => data,
        None => return,
    };

    let my_pid = std::process::id() as isize;
    unsafe {
        let poller_atomic = &*((&(*shm_data).poller_pid) as *const ngx_atomic_t
            as *const std::sync::atomic::AtomicIsize);
        let _ = poller_atomic.compare_exchange(my_pid, 0, Ordering::SeqCst, Ordering::SeqCst);
    }
    IS_POLLER.store(false, Ordering::SeqCst);
}

/// Parse a CIDR string like "192.168.1.0/24" or "2001:db8::/32"
/// Returns (network_bytes, family, prefix_len)
pub fn parse_cidr(cidr: &str) -> Option<([u8; 16], u8, u8)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let prefix_len: u8 = parts[1].parse().ok()?;

    // Try IPv4 first
    if let Ok(v4) = parts[0].parse::<Ipv4Addr>() {
        if prefix_len > 32 {
            return None;
        }
        let network = apply_ipv4_mask(&v4.octets(), prefix_len);
        let mut addr = [0u8; 16];
        addr[..4].copy_from_slice(&network);
        return Some((addr, 4, prefix_len));
    }

    // Try IPv6
    if let Ok(v6) = parts[0].parse::<Ipv6Addr>() {
        if prefix_len > 128 {
            return None;
        }
        let network = apply_ipv6_mask(&v6.octets(), prefix_len);
        return Some((network, 6, prefix_len));
    }

    None
}

fn get_metrics_shm() -> Option<*mut MetricsShm> {
    let zone = METRICS_SHM_ZONE.load(Ordering::SeqCst);
    if zone.is_null() {
        return None;
    }
    unsafe {
        let data = (*zone).data.cast::<MetricsShm>();
        if data.is_null() { None } else { Some(data) }
    }
}

/// Fixed size for the metrics zone. Must exceed one OS page plus the slab pool
/// header; a 4KB zone leaves zero allocatable pages on typical 4096-byte pages.
const METRICS_SHM_SIZE: usize = 8192;

/// Second shared zone for counters (fixed size; safe across `ShmData` upgrades).
///
/// # Safety
/// Valid `ngx_conf_t` from NGINX configuration.
pub unsafe fn init_metrics_shm_zone(cf: *mut ngx::ffi::ngx_conf_t) -> Result<(), ()> {
    let name: ngx_str_t = ngx_string!("crowdsec_metrics");
    let shm_zone = ngx::ffi::ngx_shared_memory_add(
        cf,
        &name as *const _ as *mut _,
        METRICS_SHM_SIZE,
        &raw const crate::ngx_http_crowdsec_module as *mut _,
    );
    if shm_zone.is_null() {
        return Err(());
    }
    (*shm_zone).init = Some(metrics_zone_init);
    (*shm_zone).data = ptr::null_mut();
    METRICS_SHM_ZONE.store(shm_zone, Ordering::SeqCst);
    Ok(())
}

unsafe extern "C" fn metrics_zone_init(
    shm_zone: *mut ngx_shm_zone_t,
    data: *mut std::ffi::c_void,
) -> ngx_int_t {
    if !data.is_null() {
        (*shm_zone).data = data;
        return NGX_OK as ngx_int_t;
    }

    let shpool = (*shm_zone).shm.addr as *mut ngx_slab_pool_t;
    if shpool.is_null() {
        return ngx::ffi::NGX_ERROR as ngx_int_t;
    }

    let sz = std::mem::size_of::<MetricsShm>();
    let p = ngx_slab_alloc_locked(shpool, sz);
    if p.is_null() {
        eprintln!(
            "crowdsec: warning: failed to allocate metrics SHM; counters disabled"
        );
        return NGX_OK as ngx_int_t;
    }

    ptr::write(
        p.cast::<MetricsShm>(),
        MetricsShm {
            http_lookups: AtomicU64::new(0),
            http_bans: AtomicU64::new(0),
            http_captcha: AtomicU64::new(0),
            http_bypass: AtomicU64::new(0),
            lapi_poll_ok: AtomicU64::new(0),
            lapi_poll_err: AtomicU64::new(0),
            lapi_last_success_unix_secs: AtomicU64::new(0),
        },
    );

    (*shm_zone).data = p;
    NGX_OK as ngx_int_t
}

#[inline]
pub fn metrics_inc_http_lookup() {
    let Some(p) = get_metrics_shm() else {
        return;
    };
    unsafe {
        (*p).http_lookups.fetch_add(1, Ordering::Relaxed);
    }
}

#[inline]
pub fn metrics_inc_http_ban() {
    let Some(p) = get_metrics_shm() else {
        return;
    };
    unsafe {
        (*p).http_bans.fetch_add(1, Ordering::Relaxed);
    }
}

#[inline]
pub fn metrics_inc_http_captcha() {
    let Some(p) = get_metrics_shm() else {
        return;
    };
    unsafe {
        (*p).http_captcha.fetch_add(1, Ordering::Relaxed);
    }
}

#[inline]
pub fn metrics_inc_http_bypass() {
    let Some(p) = get_metrics_shm() else {
        return;
    };
    unsafe {
        (*p).http_bypass.fetch_add(1, Ordering::Relaxed);
    }
}

#[inline]
pub fn metrics_inc_lapi_poll_ok() {
    let Some(p) = get_metrics_shm() else {
        return;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    unsafe {
        (*p).lapi_poll_ok.fetch_add(1, Ordering::Relaxed);
        (*p).lapi_last_success_unix_secs
            .store(now, Ordering::Relaxed);
    }
}

#[inline]
pub fn metrics_inc_lapi_poll_err() {
    let Some(p) = get_metrics_shm() else {
        return;
    };
    unsafe {
        (*p).lapi_poll_err.fetch_add(1, Ordering::Relaxed);
    }
}

/// Snapshot for Prometheus exposition (best-effort relaxed reads).
pub fn metrics_prometheus_snapshot() -> (u64, u64, u64, u64, u64, u64, u64, u32) {
    let Some(p) = get_metrics_shm() else {
        return (0, 0, 0, 0, 0, 0, 0, get_count());
    };
    unsafe {
        (
            (*p).http_lookups.load(Ordering::Relaxed),
            (*p).http_bans.load(Ordering::Relaxed),
            (*p).http_captcha.load(Ordering::Relaxed),
            (*p).http_bypass.load(Ordering::Relaxed),
            (*p).lapi_poll_ok.load(Ordering::Relaxed),
            (*p).lapi_poll_err.load(Ordering::Relaxed),
            (*p).lapi_last_success_unix_secs.load(Ordering::Relaxed),
            get_count(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_ip() {
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();
        let ip3: IpAddr = "192.168.1.1".parse().unwrap();

        let h1 = hash_ip(&ip1);
        let h2 = hash_ip(&ip2);
        let h3 = hash_ip(&ip3);

        assert!(h1 >= 2);
        assert!(h2 >= 2);
        assert_eq!(h1, h3); // Same IP should have same hash
        assert_ne!(h1, h2); // Different IPs should (likely) have different hashes
    }

    #[test]
    fn test_apply_ipv4_mask() {
        let addr = [192, 168, 1, 100];

        assert_eq!(apply_ipv4_mask(&addr, 32), [192, 168, 1, 100]);
        assert_eq!(apply_ipv4_mask(&addr, 24), [192, 168, 1, 0]);
        assert_eq!(apply_ipv4_mask(&addr, 16), [192, 168, 0, 0]);
        assert_eq!(apply_ipv4_mask(&addr, 8), [192, 0, 0, 0]);
        assert_eq!(apply_ipv4_mask(&addr, 0), [0, 0, 0, 0]);
    }

    #[test]
    fn test_parse_cidr() {
        let (network, family, prefix) = parse_cidr("192.168.1.0/24").unwrap();
        assert_eq!(family, 4);
        assert_eq!(prefix, 24);
        assert_eq!(&network[..4], &[192, 168, 1, 0]);

        let (network, family, prefix) = parse_cidr("10.0.0.0/8").unwrap();
        assert_eq!(family, 4);
        assert_eq!(prefix, 8);
        assert_eq!(&network[..4], &[10, 0, 0, 0]);

        // Test IPv6
        let result = parse_cidr("2001:db8::/32");
        assert!(result.is_some());
        let (_, family, prefix) = result.unwrap();
        assert_eq!(family, 6);
        assert_eq!(prefix, 32);

        let (network, family, prefix) = parse_cidr("0.0.0.0/0").unwrap();
        assert_eq!((family, prefix), (4, 0));
        assert_eq!(&network[..4], &[0, 0, 0, 0]);

        let (_, family, prefix) = parse_cidr("2001:db8::1/128").unwrap();
        assert_eq!((family, prefix), (6, 128));
    }

    #[test]
    fn test_expiration_uses_supplied_time() {
        let mut entry = ShmHashEntry::empty();
        entry.expires = 100;
        assert!(!entry.is_expired_at(100));
        assert!(entry.is_expired_at(101));
        entry.expires = 0;
        assert!(!entry.is_expired_at(i64::MAX));
    }

    #[test]
    fn test_shm_entry_size() {
        // Verify entry size is what we expect (48 bytes with alignment)
        assert_eq!(std::mem::size_of::<ShmHashEntry>(), 48);
    }

    #[test]
    fn test_decision_type_bitmask() {
        // Test individual bits
        assert_eq!(DecisionType::Ban.to_bit(), DECISION_BIT_BAN);
        assert_eq!(DecisionType::Captcha.to_bit(), DECISION_BIT_CAPTCHA);
        assert_eq!(DecisionType::Unknown.to_bit(), 0);

        // Test priority: Ban > Captcha
        assert_eq!(
            DecisionType::from_bitmask(DECISION_BIT_BAN),
            DecisionType::Ban
        );
        assert_eq!(
            DecisionType::from_bitmask(DECISION_BIT_CAPTCHA),
            DecisionType::Captcha
        );

        // Combined: Ban takes priority
        let combined = DECISION_BIT_BAN | DECISION_BIT_CAPTCHA;
        assert_eq!(DecisionType::from_bitmask(combined), DecisionType::Ban);

        // Empty bitmask
        assert_eq!(DecisionType::from_bitmask(0), DecisionType::Unknown);
    }

    #[test]
    fn test_entry_decision_types() {
        let mut entry = ShmHashEntry::empty();

        // Initially no decisions
        assert!(!entry.has_decisions());
        assert_eq!(entry.decision_type(), DecisionType::Unknown);

        // Add captcha
        entry.add_decision_type(DecisionType::Captcha);
        assert!(entry.has_decisions());
        assert!(entry.has_decision_type(DecisionType::Captcha));
        assert!(!entry.has_decision_type(DecisionType::Ban));
        assert_eq!(entry.decision_type(), DecisionType::Captcha);

        // Add ban (higher priority)
        entry.add_decision_type(DecisionType::Ban);
        assert!(entry.has_decision_type(DecisionType::Ban));
        assert!(entry.has_decision_type(DecisionType::Captcha));
        assert_eq!(entry.decision_type(), DecisionType::Ban); // Ban takes priority

        // Remove ban, captcha remains
        entry.remove_decision_type(DecisionType::Ban);
        assert!(!entry.has_decision_type(DecisionType::Ban));
        assert!(entry.has_decision_type(DecisionType::Captcha));
        assert_eq!(entry.decision_type(), DecisionType::Captcha);

        // Remove captcha, no decisions left
        entry.remove_decision_type(DecisionType::Captcha);
        assert!(!entry.has_decisions());
    }
}
