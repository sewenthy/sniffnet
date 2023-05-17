//! Module containing functions executed by the thread in charge of parsing sniffed packets and
//! inserting them in the shared map.

use std::sync::{Arc, Mutex};

use etherparse::PacketHeaders;
use pcap::{Active, Capture, Device};
use maxminddb::Reader;

use crate::enums::traffic_type::TrafficType;
use crate::structs::address_port_pair::AddressPortPair;
use crate::structs::filters::Filters;
use crate::utility::countries::{COUNTRY_MMDB, get_country_code};
use crate::utility::manage_packets::{
    analyze_network_header, analyze_transport_header, is_broadcast_address, is_multicast_address,
};
use crate::{AppProtocol, InfoTraffic, IpVersion, TransProtocol};
use crate::structs::info_address_port_pair::InfoAddressPortPair;

/// The calling thread enters in a loop in which it waits for network packets, parses them according
/// to the user specified filters, and inserts them into the shared map variable.
pub fn parse_packets_loop(
    current_capture_id: &Arc<Mutex<u16>>,
    device: Device,
    mut cap: Capture<Active>,
    filters: &Filters,
    info_traffic_mutex: &Arc<Mutex<InfoTraffic>>,
) {
    let capture_id = *current_capture_id.lock().unwrap();

    let mut my_interface_addresses = Vec::new();
    for address in device.addresses {
        my_interface_addresses.push(address.addr.to_string());
    }

    let network_layer_filter = filters.ip;
    let transport_layer_filter = filters.transport;
    let app_layer_filter = filters.application;

    let mut port1 = 0;
    let mut port2 = 0;
    let mut exchanged_bytes: u128 = 0;
    let mut network_protocol;
    let mut transport_protocol;
    let mut application_protocol;
    let mut traffic_type;
    let mut skip_packet;
    let mut reported_packet;

    let country_db_reader = maxminddb::Reader::from_source(COUNTRY_MMDB).unwrap();

    loop {
        match cap.next_packet() {
            Err(_) => {
                if *current_capture_id.lock().unwrap() != capture_id {
                    return;
                }
                continue;
            }
            Ok(packet) => {
                if *current_capture_id.lock().unwrap() != capture_id {
                    return;
                }
                match PacketHeaders::from_ethernet_slice(&packet) {
                    Err(_) => {
                        continue;
                    }
                    Ok(value) => {
                        let mut address1 = String::new();
                        let mut address2 = String::new();
                        network_protocol = IpVersion::Other;
                        transport_protocol = TransProtocol::Other;
                        application_protocol = AppProtocol::Other;
                        traffic_type = TrafficType::Other;
                        skip_packet = false;
                        reported_packet = false;

                        analyze_network_header(
                            value.ip,
                            &mut exchanged_bytes,
                            &mut network_protocol,
                            &mut address1,
                            &mut address2,
                            &mut skip_packet,
                        );
                        if skip_packet {
                            continue;
                        }

                        analyze_transport_header(
                            value.transport,
                            &mut port1,
                            &mut port2,
                            &mut application_protocol,
                            &mut transport_protocol,
                            &mut skip_packet,
                        );
                        if skip_packet {
                            continue;
                        }

                        if my_interface_addresses.contains(&address1) {
                            traffic_type = TrafficType::Outgoing;
                        } else if my_interface_addresses.contains(&address2) {
                            traffic_type = TrafficType::Incoming;
                        } else if is_multicast_address(&address2) {
                            traffic_type = TrafficType::Multicast;
                        } else if is_broadcast_address(&address2) {
                            traffic_type = TrafficType::Broadcast;
                        }

                        let key: AddressPortPair = AddressPortPair::new(
                            address1,
                            port1,
                            address2,
                            port2,
                            transport_protocol,
                        );

                        if (network_layer_filter.eq(&IpVersion::Other)
                            || network_layer_filter.eq(&network_protocol))
                            && (transport_layer_filter.eq(&TransProtocol::Other)
                                || transport_layer_filter.eq(&transport_protocol))
                            && (app_layer_filter.eq(&AppProtocol::Other)
                                || app_layer_filter.eq(&application_protocol))
                        {
                            // if (port1 >= lowest_port && port1 <= highest_port)
                            //     || (port2 >= lowest_port && port2 <= highest_port) {
                            /* START SELECTION */
                            /* this is expected to fail because of struct punning */
                            let now = chrono::Local::now();
                            let very_long_address = key.address1.len() > 25 || key.address2.len() > 25;
                            let mut info_traffic = info_traffic_mutex
                                .lock()
                                .expect("Error acquiring mutex\n\r");
                            let len = info_traffic.map.len();
                            let index = info_traffic.map.get_index_of(&key).unwrap_or(len);
                            let country = if index == len {
                                // first occurrence of key => retrieve country code
                                get_country_code(traffic_type, &key, &country_db_reader)
                            } else {
                                // this key already occurred
                                String::new()
                            };
                            let is_already_featured = info_traffic.favorites_last_interval.contains(&index);
                            let mut update_favorites_featured = false;
                            info_traffic
                                .map
                                .entry(key)
                                .and_modify(|info| {
                                    info.transmitted_bytes += exchanged_bytes;
                                    info.transmitted_packets += 1;
                                    info.final_timestamp = now;
                                    if info.is_favorite && !is_already_featured {
                                        update_favorites_featured = true;
                                    }
                                })
                                .or_insert(InfoAddressPortPair {
                                    transmitted_bytes: exchanged_bytes,
                                    transmitted_packets: 1,
                                    initial_timestamp: now,
                                    final_timestamp: now,
                                    app_protocol: application_protocol,
                                    very_long_address,
                                    traffic_type, /* punning occurs here */
                                    country,
                                    index,
                                    is_favorite: false,
                                });
                            info_traffic.addresses_last_interval.insert(index);
                            if update_favorites_featured {
                                info_traffic.favorites_last_interval.insert(index);
                            }
                            /* END SELECTION */
                            reported_packet = true;
                            // }
                        }

                        let mut info_traffic = info_traffic_mutex
                            .lock()
                            .expect("Error acquiring mutex\n\r");
                        //increment number of sniffed packets and bytes
                        info_traffic.all_packets += 1;
                        info_traffic.all_bytes += exchanged_bytes;

                        if reported_packet {
                            //increment the packet count for the sniffed app protocol
                            info_traffic
                                .app_protocols
                                .entry(application_protocol)
                                .and_modify(|n| *n += 1)
                                .or_insert(1);

                            if traffic_type == TrafficType::Outgoing {
                                //increment number of sent packets and bytes
                                info_traffic.tot_sent_packets += 1;
                                info_traffic.tot_sent_bytes += exchanged_bytes;
                            } else {
                                //increment number of received packets and bytes
                                info_traffic.tot_received_packets += 1;
                                info_traffic.tot_received_bytes += exchanged_bytes;
                            }
                        }
                    }
                }
            }
        }
    }
}
