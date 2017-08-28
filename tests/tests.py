import unittest

import cvedetails_client as cc

class TestNormalizeString(unittest.TestCase):
    def test_simple(self):
        res = cc.normalize_string('<Something,!>')
        self.assertEqual('Something', res)
    def test_empty(self):
        self.assertEqual('', cc.normalize_string(''))

class TestBlackBox(unittest.TestCase):
    queries = [(['Apache', 'Http Server', '2.4.9'], ['CVE-2014-0231', 'CVE-2016-8743', 'CVE-2015-3185', 'CVE-2014-0226', 'CVE-2016-2161', 'CVE-2014-8109', 'CVE-2014-0117', 'CVE-2017-9788', 'CVE-2016-0736', 'CVE-2014-0118', 'CVE-2014-3523']),
                (['Nginx', 'Nginx', '1.8.0'], ['CVE-2016-0746', 'CVE-2016-0742', 'CVE-2016-0747']),
                (['Openbsd', 'Openssh', '7.2', 'P2'], ['CVE-2015-8325', 'CVE-2016-6210', 'CVE-2016-6515', 'CVE-2016-8858']),
                (['Openbsd', 'Openssh', '7.2'], ['CVE-2016-8858']),
                (['Microsoft', 'Server Message Block', '1.0'], ['CVE-2017-0143', 'CVE-2017-0145', 'CVE-2017-0148', 'CVE-2017-0147', 'CVE-2017-0146', 'CVE-2017-0144'])
                ]

    def test_examples(self):
        for example, result in self.queries:
            args = vars(cc.args_parser.parse_args(example))
            self.assertSetEqual(set(result),
                                set(cc.main(**args).keys()))

class Test:
    pass
    
