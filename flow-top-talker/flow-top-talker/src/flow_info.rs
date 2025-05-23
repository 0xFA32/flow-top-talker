use std::collections::BinaryHeap;
use std::collections::binary_heap::Iter;

use flow_top_talker_common::common_types::FlowKey;

/// Aggregated flow info.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct FlowInfo {
    pub throughput: u64,
    pub src_addr: u32,
    pub dest_addr: u32,
    pub src_port: u16,
    pub dest_port: u16,
    pub protocol: u8,
}


impl PartialOrd for FlowInfo {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        other.throughput.partial_cmp(&self.throughput)
    }
}

impl Ord for FlowInfo {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
       other.throughput.cmp(&self.throughput)
    }
}

/// Limited size max heap based on throughput.
pub struct LimitedMaxHeap {
    top_n: usize,
    heap: BinaryHeap<FlowInfo>,
}

impl LimitedMaxHeap {
    pub fn new(top_n: usize) -> Self {
        Self {
            top_n,
            heap: BinaryHeap::new(),
        }
    }

    pub fn add(
        &mut self,
        flow_key: &FlowKey,
        total_throughput: u64,
    ) {
        if self.heap.len() == self.top_n {
            let lowest_flow = self.heap.peek().unwrap();
            if lowest_flow.throughput < total_throughput {
                self.heap.pop();
                self.heap.push(FlowInfo {
                    src_addr: flow_key.src_addr,
                    dest_addr: flow_key.dest_addr,
                    src_port: flow_key.src_port,
                    dest_port: flow_key.dest_port,
                    protocol: flow_key.protocol,
                    throughput: total_throughput,
                });
            }
        } else {
            self.heap.push(FlowInfo {
                src_addr: flow_key.src_addr,
                dest_addr: flow_key.dest_addr,
                src_port: flow_key.src_port,
                dest_port: flow_key.dest_port,
                protocol: flow_key.protocol,
                throughput: total_throughput,
            });                                
        }   
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.heap.len()
    }

    #[cfg(test)]
    fn pop(&mut self) -> Option<FlowInfo> {
        self.heap.pop()
    }

    pub fn clear(&mut self) {
        self.heap.clear()
    }

    pub fn liter(&self) -> Liter {
        Liter { iter: self.heap.iter() }
    }
}

/// Iterator for the limited max heap.
pub struct Liter<'a> {
    iter: Iter<'a, FlowInfo>,
}

impl<'a> Iterator for Liter<'a> {
    type Item = &'a FlowInfo;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

mod tests {
    use std::collections::BinaryHeap;

    use flow_top_talker_common::common_types::FlowKey;

    use crate::{flow_info:: LimitedMaxHeap, FlowInfo};

    #[test]
    fn add_data_to_heap_2() {
        let mut heap = LimitedMaxHeap::new(2);
        let key1 = FlowKey::new(0, 0, 0, 0, 1);
        let key2 = FlowKey::new(0, 1, 0, 1, 1);
        for t in 100..200 {
            let flow_key = if t%2 == 0 { &key1 } else { &key2 };
            heap.add(flow_key, t);
        }

        assert_eq!(heap.len(), 2);
        assert_eq!(heap.pop().unwrap().throughput, 198);
        assert_eq!(heap.pop().unwrap().throughput, 199);
    }

    #[test]
    fn add_data_to_heap_5() {
        let mut heap = LimitedMaxHeap::new(5);
        let key1 = FlowKey::new(0, 0, 0, 0, 1);
        let key2 = FlowKey::new(0, 1, 0, 1, 1);
        for t in 100..200 {
            let flow_key = if t%2 == 0 { &key1 } else { &key2 };
            heap.add(flow_key, t);
        }

        assert_eq!(heap.len(), 5);
        assert_eq!(heap.pop().unwrap().throughput, 195);
        assert_eq!(heap.pop().unwrap().throughput, 196);
        assert_eq!(heap.pop().unwrap().throughput, 197);
        assert_eq!(heap.pop().unwrap().throughput, 198);
        assert_eq!(heap.pop().unwrap().throughput, 199);
    }

    #[test]
    fn add_data_to_heap_higher_flow_key() {
        let mut heap = LimitedMaxHeap::new(3);
        let key1 = FlowKey::new(0, 0, 0, 0, 1);
        let key2 = FlowKey::new(100, 100, 1000, 1000, 10);
        for t in 100..200 {
            if t%2 == 0 { 
                heap.add(&key1, t);
            } else { 
                heap.add(&key2, 1);
            };
            
        }

        assert_eq!(heap.len(), 3);
        assert_eq!(heap.pop().unwrap().throughput, 194);
        assert_eq!(heap.pop().unwrap().throughput, 196);
        assert_eq!(heap.pop().unwrap().throughput, 198);
    }
}