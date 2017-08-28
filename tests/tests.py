import unittest
from unittest.mock import MagicMock

import grab

import cvedetails_client as cc

class TestNormalizeString(unittest.TestCase):
    def test_simple(self):
        res = cc.normalize_string('<Something,!>')
        self.assertEqual('Something', res)
    def test_empty(self):
        self.assertEqual('', cc.normalize_string(''))

#@unittest.skip('Working for now')
class TestBlackBox(unittest.TestCase):
    queries = [(['Apache', 'Http Server', '2.4.9'], ['CVE-2014-0231', 'CVE-2016-8743', 'CVE-2015-3185', 'CVE-2014-0226', 'CVE-2016-2161', 'CVE-2014-8109', 'CVE-2014-0117', 'CVE-2017-9788', 'CVE-2016-0736', 'CVE-2014-0118', 'CVE-2014-3523']),
                (['Nginx', 'Nginx', '1.8.0'], ['CVE-2016-0746', 'CVE-2016-0742', 'CVE-2016-0747']),
                (['Openbsd', 'Openssh', '7.2', 'P2'], ['CVE-2015-8325', 'CVE-2016-6210', 'CVE-2016-6515', 'CVE-2016-8858']),
                (['Openbsd', 'Openssh', '7.2'], ['CVE-2016-8858']),
                (['Microsoft', 'Server Message Block', '1.0'], ['CVE-2017-0143', 'CVE-2017-0145', 'CVE-2017-0148', 'CVE-2017-0147', 'CVE-2017-0146', 'CVE-2017-0144']),
                (['Autotrace Project', 'Autotrace', '0.31.1'], []), # Этот тест не проходим на данный момент
                ]

    def test_examples(self):
        for example, result in self.queries:
            args = vars(cc.args_parser.parse_args(example))
            self.assertSetEqual(set(result),
                                set(cc.main(**args).keys()))

@unittest.mock.patch('cvedetails_client.determine_page_type')
class TestRun(unittest.TestCase):
    @unittest.mock.patch('cvedetails_client.make_json_from_page')
    @unittest.mock.patch('cvedetails_client.vulns_page')
    def test_vulns_page(self, vulns_page, make_json_from_page, determine_func):
        client = MagicMock(spec=cc.CVEDetailsClient())
        determine_func.return_value = 'vulns_page'
        cc.main('Microsoft', 'Server Message Block', '1.0', client=client)
        self.assertEqual(1, determine_func.call_count)
        self.assertEqual(1, vulns_page.call_count)
        self.assertEqual(1, make_json_from_page.call_count)
        
    @unittest.mock.patch('cvedetails_client.make_json_from_page')
    @unittest.mock.patch('cvedetails_client.search_page')
    def test_search_page(self, search_page, make_json_from_page, determine_func):
        client = MagicMock(spec=cc.CVEDetailsClient())
        determine_func.return_value = 'search_page'
        cc.main('Microsoft', 'Server Message Block', '1.0', client=client)
        self.assertEqual(1, determine_func.call_count)
        self.assertEqual(1, search_page.call_count)
        self.assertEqual(1, make_json_from_page.call_count)

    def test_error(self, determine_func):
        client = MagicMock(spec=cc.CVEDetailsClient())
        determine_func.return_value = 'error'
        self.assertEqual({}, cc.main('Microsoft', 'Server Message Block', '1.0', client=client))
        self.assertEqual(1, determine_func.call_count)

    def test_critical(self, determine_func):
        client = MagicMock(spec=cc.CVEDetailsClient())
        determine_func.return_value = ''
        self.assertEqual({}, cc.main('Microsoft', 'Server Message Block', '1.0', client=client))
        self.assertEqual(1, determine_func.call_count)
        
class TestDeterminePageType(unittest.TestCase):
    def test_grab_go_exception(self):
        client = MagicMock(spec=cc.CVEDetailsClient())
        client.g.go.side_effect = grab.error.GrabCouldNotResolveHostError
        with self.assertRaises(grab.error.GrabCouldNotResolveHostError):
            cc.determine_page_type('jhadsbfgb', client=client)
        
    def test_choices(self):
        client = MagicMock(spec=cc.CVEDetailsClient())
        m = MagicMock()
        client.g.doc.select.return_value = m
        m.text.return_value = "Vendor, Product and Version Search"
        client.g.doc.text_search.return_value = False

        self.assertEqual('search_page', cc.determine_page_type('asdfh', client=client))

        self.assertEqual(1, client.g.doc.select.call_count)
        client.g.doc.select.assert_called_once_with('//td/div/h1')
        self.assertEqual(1, m.text.call_count)

        m.text.return_value = 'Vulnerabilities'

        self.assertEqual('vulns_page', cc.determine_page_type('asdfg', client=client))

        client.g.doc.text_search.return_value = True

        self.assertEqual('error', cc.determine_page_type('asdfg', client=client))

        

        

                         
        
    
