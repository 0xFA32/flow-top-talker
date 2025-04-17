use std::collections::BinaryHeap;

use flow_top_talker_common::common_types::FlowKey;

/// Aggregated flow info.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct FlowInfo {
    pub src_addr: u32,
    pub dest_addr: u32,
    pub src_port: u16,
    pub dest_port: u16,
    pub throughput: u64,
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

pub fn add_to_heap(
    heap: &mut BinaryHeap<FlowInfo>,
    max_size: usize,
    flow_key: &FlowKey,
    total_throughput: u64,
) {
    if heap.len() == max_size {
        let lowest_flow = heap.peek().unwrap();
        if lowest_flow.throughput < total_throughput {
            heap.pop();
            heap.push(FlowInfo {
                src_addr: flow_key.src_addr,
                dest_addr: flow_key.dest_addr,
                src_port: flow_key.src_port,
                dest_port: flow_key.dest_port,
                throughput: total_throughput,
            });
        }
    } else {
        heap.push(FlowInfo {
            src_addr: flow_key.src_addr,
            dest_addr: flow_key.dest_addr,
            src_port: flow_key.src_port,
            dest_port: flow_key.dest_port,
            throughput: total_throughput,
        });                                
    }    
}

mod tests {
    use std::collections::BinaryHeap;

    use flow_top_talker_common::common_types::FlowKey;

    use crate::{add_to_heap, FlowInfo};

    #[test]
    fn add_data_to_heap_2() {
        let mut heap: BinaryHeap<FlowInfo> = BinaryHeap::new();
        let key1 = FlowKey::new(0, 0, 0, 0, 1);
        let key2 = FlowKey::new(0, 1, 0, 1, 1);
        for t in 100..200 {
            let flow_key = if t%2 == 0 { &key1 } else { &key2 };
            add_to_heap(&mut heap, 2, flow_key, t);
        }

        assert_eq!(heap.len(), 2);
        assert_eq!(heap.pop().unwrap().throughput, 198);
        assert_eq!(heap.pop().unwrap().throughput, 199);
    }

    #[test]
    fn add_data_to_heap_5() {
        let mut heap: BinaryHeap<FlowInfo> = BinaryHeap::new();
        let key1 = FlowKey::new(0, 0, 0, 0, 1);
        let key2 = FlowKey::new(0, 1, 0, 1, 1);
        for t in 100..200 {
            let flow_key = if t%2 == 0 { &key1 } else { &key2 };
            add_to_heap(&mut heap, 5, flow_key, t);
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
        let mut heap: BinaryHeap<FlowInfo> = BinaryHeap::new();
        let key1 = FlowKey::new(0, 0, 0, 0, 1);
        let key2 = FlowKey::new(100, 100, 1000, 1000, 10);
        for t in 100..200 {
            if t%2 == 0 { 
                add_to_heap(&mut heap, 3, &key1, t);
            } else { 
                add_to_heap(&mut heap, 3, &key2, 1);
            };
            
        }

        assert_eq!(heap.len(), 3);
        assert_eq!(heap.pop().unwrap().throughput, 194);
        assert_eq!(heap.pop().unwrap().throughput, 196);
        assert_eq!(heap.pop().unwrap().throughput, 198);
    }
}