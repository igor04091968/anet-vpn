use dashmap::DashSet;
use std::net::Ipv4Addr;
use std::sync::Arc;

#[derive(Clone)]
pub struct IpPool {
    pub network: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub server: Ipv4Addr,
    pub mtu: u16,
    used: Arc<DashSet<Ipv4Addr>>,
}

impl IpPool {
    pub fn new(
        network: Ipv4Addr,
        netmask: Ipv4Addr,
        gateway: Ipv4Addr,
        server: Ipv4Addr,
        mtu: u16,
    ) -> Self {
        Self {
            network,
            netmask,
            gateway,
            server,
            mtu,
            used: Arc::new(DashSet::new()),
        }
    }

    pub fn allocate(&self) -> Option<Ipv4Addr> {
        let net = u32::from(self.network);
        let mask = u32::from(self.netmask);
        let gw = self.gateway;
        let srv = self.server;

        for host in 1..=u32::MAX {
            let candidate = net | host;
            if (candidate & mask) != (net & mask) {
                break;
            }
            let ip = Ipv4Addr::from(candidate);

            if ip == gw || ip == srv {
                continue;
            }
            if candidate == (net | !mask) {
                break; // subnet broadcast is not a host address
            }
            // Claim atomically: parallel handshakes must never share an IP.
            if self.used.insert(ip) {
                return Some(ip);
            }
        }
        None
    }

    pub fn release(&self, ip: Ipv4Addr) -> bool {
        self.used.remove(&ip).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(network: &str, mask: &str, gateway: &str, server: &str) -> IpPool {
        IpPool::new(
            network.parse().unwrap(),
            mask.parse().unwrap(),
            gateway.parse().unwrap(),
            server.parse().unwrap(),
            1400,
        )
    }

    #[test]
    fn excludes_gateway_server_and_broadcast_and_releases_once() {
        let main_pool = pool("10.0.0.0", "255.255.255.0", "10.0.0.1", "10.0.0.2");
        assert_eq!(main_pool.allocate(), Some("10.0.0.3".parse().unwrap()));
        assert!(main_pool.release("10.0.0.3".parse().unwrap()));
        assert!(!main_pool.release("10.0.0.3".parse().unwrap()));

        let small = pool("192.0.2.0", "255.255.255.252", "192.0.2.1", "192.0.2.2");
        assert_eq!(small.allocate(), None);
    }

    #[test]
    fn concurrent_allocations_are_unique() {
        let pool = pool("10.1.0.0", "255.255.255.0", "10.1.0.1", "10.1.0.2");
        let threads: Vec<_> = (0..32)
            .map(|_| {
                let pool = pool.clone();
                std::thread::spawn(move || pool.allocate().unwrap())
            })
            .collect();
        let allocated: std::collections::HashSet<_> =
            threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(allocated.len(), 32);
    }
}
