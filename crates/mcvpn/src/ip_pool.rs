use crate::error::{VpnError, VpnResult};
use std::collections::{BTreeSet, HashSet};
use std::net::Ipv4Addr;

/// Allocator over a CIDR (default 100.64.0.0/10): O(log n) with a free list,
/// lowest-first reuse so addresses look like a normally filling server.
pub struct IpPool {
    base: u32,
    prefix: u8,
    used: HashSet<u32>,
    free: BTreeSet<u32>,
    next: u32,
}

impl IpPool {
    pub fn new(cidr: &str) -> VpnResult<Self> {
        let (net, prefix) = cidr
            .split_once('/')
            .ok_or_else(|| VpnError::Device(format!("bad cidr {cidr}")))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| VpnError::Device(format!("bad prefix in {cidr}")))?;
        if !(8..=32).contains(&prefix) {
            return Err(VpnError::Device("prefix must be 8..=32".into()));
        }
        let net: Ipv4Addr = net
            .parse()
            .map_err(|_| VpnError::Device(format!("bad network in {cidr}")))?;
        let mask: u32 = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        let base = u32::from(net) & mask;
        Ok(IpPool {
            base,
            prefix,
            used: HashSet::new(),
            free: BTreeSet::new(),
            next: base + 2,
        })
    }

    pub fn gateway(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.base + 1)
    }

    pub fn netmask(&self) -> Ipv4Addr {
        let mask: u32 = if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix)
        };
        Ipv4Addr::from(mask)
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        (u32::from(ip) & self.mask_u32()) == self.base
    }

    /// Network address of the pool, as a u32 (for lock-free hot-path checks).
    pub fn base_u32(&self) -> u32 {
        self.base
    }

    /// Netmask of the pool, as a u32.
    pub fn mask_u32(&self) -> u32 {
        if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix)
        }
    }

    pub fn allocate(&mut self) -> Option<Ipv4Addr> {
        // Lowest-first allocation: deterministic and reuses released IPs.
        if let Some(&ip) = self.free.iter().next() {
            self.free.remove(&ip);
            self.used.insert(ip);
            return Some(Ipv4Addr::from(ip));
        }
        let first = self.base + 2;
        let last = self.broadcast() - 1;
        if last < first {
            return None;
        }
        if self.next <= last && self.used.insert(self.next) {
            let ip = self.next;
            self.next += 1;
            return Some(Ipv4Addr::from(ip));
        }
        // Fully handed out and nothing freed yet.
        None
    }

    fn broadcast(&self) -> u32 {
        let host_bits = 32 - self.prefix;
        let base = self.base;
        if host_bits >= 32 {
            u32::MAX
        } else {
            base | ((1u32 << host_bits) - 1)
        }
    }

    pub fn release(&mut self, ip: Ipv4Addr) {
        let raw = u32::from(ip);
        if self.used.remove(&raw) {
            self.free.insert(raw);
        }
    }

    pub fn in_use(&self) -> usize {
        self.used.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_from_cgnat() {
        let mut p = IpPool::new("100.64.0.0/10").unwrap();
        assert_eq!(p.gateway().to_string(), "100.64.0.1");
        let a = p.allocate().unwrap();
        let b = p.allocate().unwrap();
        assert_eq!(a.to_string(), "100.64.0.2");
        assert_eq!(b.to_string(), "100.64.0.3");
        assert_eq!(p.in_use(), 2);
        p.release(a);
        let c = p.allocate().unwrap();
        assert_eq!(c.to_string(), "100.64.0.2");
        assert!(p.contains("100.100.1.1".parse().unwrap()));
        assert!(!p.contains("100.0.0.1".parse().unwrap()));
    }

    #[test]
    fn small_pool_exhausts() {
        let mut p = IpPool::new("10.0.0.0/30").unwrap();
        // /30 = 4 addresses: network, gateway, one host, broadcast.
        assert!(p.allocate().is_some());
        assert!(p.allocate().is_none());
        let mut p = IpPool::new("10.0.0.0/29").unwrap();
        for _ in 0..5 {
            assert!(p.allocate().is_some());
        }
        assert!(p.allocate().is_none());
    }
}
