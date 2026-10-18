from __future__ import annotations

import unittest
import xml.etree.ElementTree as ET

from lab.libvirt.settings import Settings
from lab.packer.artifacts import ImageError


def network(cidr_address='192.168.100.1', mask='255.255.255.0', bridge='foreign'):
    return ET.fromstring(f"<network><bridge name='{bridge}'/><ip address='{cidr_address}' netmask='{mask}'/></network>")


class SettingsTests(unittest.TestCase):
    def select(self, settings, *, networks=None, addresses=None, routes=None):
        settings.select_subnet({'networks': networks or {}}, addresses or [], routes or [])

    def test_distinct_cluster_resources_and_stable_short_bridge_names(self):
        first, second = Settings('dev'), Settings('prod')
        for attribute in ('hostname_prefix', 'pool_name', 'pool', 'network', 'bridge', 'filter'):
            self.assertNotEqual(getattr(first, attribute), getattr(second, attribute))
        self.assertLessEqual(len(first.bridge), 15)
        self.assertEqual(first.bridge, Settings('dev').bridge)
        self.assertEqual(Settings().pool_name, 'autonomous-rke2-lab')

    def test_validate_names_private_subnet_size_and_reserved_cidrs(self):
        for kwargs in ({'cluster': '../other'}, {'cluster': 'Upper'},
                       {'hostname_prefix': 'bad.name'}, {'hostname_prefix': 'x' * 62},
                       {'network': "bad'network"}, {'subnet': '192.168.1.1/24'},
                       {'subnet': '192.168.1.0/29'}, {'subnet': '8.8.8.0/24'},
                       {'subnet': 'fd00::/64'}, {'reserved_cidrs': ['not-a-cidr']}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ImageError):
                Settings(**kwargs)

    def test_detects_equal_contained_and_containing_libvirt_networks(self):
        for subnet in ('192.168.100.0/24', '192.168.100.0/25', '192.168.0.0/16'):
            with self.subTest(subnet=subnet), self.assertRaisesRegex(ImageError, 'libvirt network other'):
                self.select(Settings(subnet=subnet), networks={'other': network()})

    def test_libvirt_prefix_attribute_and_unknown_mask(self):
        xml = ET.fromstring("<network><ip address='172.20.0.1' prefix='20'/></network>")
        with self.assertRaisesRegex(ImageError, 'overlaps'):
            self.select(Settings(subnet='172.20.1.0/24'), networks={'inactive': xml})
        xml = ET.fromstring("<network><ip address='172.20.0.1'/></network>")
        with self.assertRaisesRegex(ImageError, 'cannot determine subnet'):
            self.select(Settings(), networks={'unknown': xml})

    def test_inactive_libvirt_network_routes_are_reserved(self):
        xml = ET.fromstring("<network><route address='172.21.0.0' prefix='16' gateway='192.168.1.1'/></network>")
        with self.assertRaisesRegex(ImageError, 'libvirt network inactive route'):
            self.select(Settings(subnet='172.21.4.0/24'), networks={'inactive': xml})

    def test_host_interfaces_routes_and_explicit_external_kubernetes_ranges(self):
        cases = [
            ({'addresses': [{'ifname': 'eno1', 'addr_info': [
                {'family': 'inet', 'local': '172.20.1.50', 'prefixlen': 24}]}]}, 'host interface eno1'),
            ({'routes': [{'dst': '172.20.0.0/16', 'dev': 'vpn0'}]}, 'host route via vpn0'),
            ({'routes': [{'dst': '172.20.1.10', 'dev': 'cni0'}]}, 'host route via cni0'),
            ({}, '--reserved-cidr'),
        ]
        for kwargs, source in cases:
            options = {'reserved_cidrs': ['172.20.0.0/16']} if source == '--reserved-cidr' else {}
            with self.subTest(source=source), self.assertRaisesRegex(ImageError, source):
                self.select(Settings(subnet='172.20.1.0/24', **options), **kwargs)

    def test_rejects_image_pod_service_ranges_and_their_supernets(self):
        for subnet in ('10.42.1.0/24', '10.43.0.0/16', '10.0.0.0/8'):
            with self.subTest(subnet=subnet), self.assertRaisesRegex(ImageError, 'Kubernetes pod/service'):
                self.select(Settings(subnet=subnet))

    def test_auto_selection_avoids_existing_ranges_and_ignores_default_routes(self):
        settings = Settings('second')
        self.select(settings, networks={'first': network('192.168.250.1')},
                    routes=[{'dst': 'default', 'dev': 'eno1'},
                            {'dst': '0.0.0.0/0', 'dev': 'eno1'},
                            {'dst': '172.16.0.0/24', 'dev': 'vpn0'}])
        self.assertEqual(str(settings.subnet), '172.16.1.0/24')

    def test_no_available_auto_subnet_fails(self):
        with self.assertRaisesRegex(ImageError, 'no unused private'):
            self.select(Settings(reserved_cidrs=['172.16.0.0/12', '192.168.0.0/16', '10.0.0.0/8']))

    def test_resume_inherits_configuration_and_ignores_only_its_own_network(self):
        first = Settings('dev', hostname_prefix='compute-', network='dev-net', subnet='172.22.8.0/23')
        saved = {'configuration': first.document()}
        resumed = Settings('dev', saved=saved)
        self.assertEqual(first.document(), resumed.document())
        self.select(resumed, networks={'dev-net': network('172.22.8.1', '255.255.254.0', first.bridge)},
                    addresses=[{'ifname': first.bridge, 'addr_info': [
                        {'family': 'inet', 'local': '172.22.8.1', 'prefixlen': 23}]}],
                    routes=[{'dst': '172.22.8.0/23', 'dev': first.bridge}])
        with self.assertRaisesRegex(ImageError, 'libvirt network other'):
            self.select(resumed, networks={'other': network('172.22.9.1')})
        for option in ({'hostname_prefix': 'different-'}, {'network': 'other'},
                       {'subnet': '172.23.0.0/24'}, {'reserved_cidrs': ['192.168.0.0/16']}):
            with self.subTest(option=option), self.assertRaisesRegex(ImageError, 'saved .* differs'):
                Settings('dev', saved=saved, **option)

    def test_non_24_subnet_addresses_and_network_xml(self):
        settings = Settings('qa', subnet='172.24.12.0/23')
        self.assertEqual(settings.gateway, '172.24.12.1')
        self.assertEqual(settings.address(3), '172.24.12.14')
        xml = ET.fromstring(settings.network_xml())
        self.assertEqual(xml.find('ip').get('netmask'), '255.255.254.0')
        self.assertIsNone(xml.find('forward'))
        self.assertEqual(xml.find('dns').get('enable'), 'no')

    def test_corrupt_saved_settings_are_rejected(self):
        for state in ([1], {'configuration': []}, {'configuration': {}},
                      {'configuration': {'cluster': 'dev', 'network': 'dev-net'}}):
            with self.subTest(state=state), self.assertRaisesRegex(ImageError, 'invalid saved'):
                Settings('dev', saved=state)

    def test_count_capacity_prevents_broadcast_and_cross_subnet_addresses(self):
        settings = Settings(subnet='192.168.100.0/28')
        settings.validate_nodes(4)
        self.assertEqual(settings.address(3), '192.168.100.14')
        with self.assertRaisesRegex(ImageError, 'capacity is 4'):
            settings.validate_nodes(5)
        with self.assertRaisesRegex(ImageError, 'exceed usable subnet'):
            settings.address(4)
        for count in (0, -1, True, 1.2):
            with self.subTest(count=count), self.assertRaisesRegex(ImageError, 'positive integer'):
                settings.validate_nodes(count)

    def test_automatic_subnet_expands_for_larger_node_counts(self):
        settings = Settings('large')
        settings.select_subnet({'networks': {}}, [], [], count=500)
        self.assertEqual(str(settings.subnet), '192.168.250.0/23')
        self.assertEqual(settings.address(499), '192.168.251.254')
        with self.assertRaisesRegex(ImageError, 'capacity is 500'):
            settings.validate_nodes(501)

    def test_hostname_length_includes_growing_numeric_suffix(self):
        settings = Settings(hostname_prefix='a' * 61, subnet='192.168.100.0/24')
        settings.validate_nodes(99)
        with self.assertRaisesRegex(ImageError, '63 characters'):
            settings.validate_nodes(100)

    def test_existing_image_catalog_capacity_checked_before_provisioning(self):
        settings = Settings('large', subnet='172.24.0.0/21')
        settings.validate_nodes(1024)
        with self.assertRaisesRegex(ImageError, '1024 members'):
            settings.validate_nodes(1025)


if __name__ == '__main__':
    unittest.main()
