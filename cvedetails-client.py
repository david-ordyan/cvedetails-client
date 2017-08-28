#!/usr/bin/env python3
import re, logging, argparse
import grab

args_parser = argparse.ArgumentParser(
    description='Search cvedetails.com for CVEs by vendor, product and version, optionally by patch.')
args_parser.add_argument('vendor')
args_parser.add_argument('product')
args_parser.add_argument('version')
args_parser.add_argument('patch', default='', nargs='?')

logger = logging.getLogger(__name__)

def normalize_string(string):
    return re.sub(r'[^a-zA-Z0-9]', '', string)
    
class CVEDetailsClient:

    search_url = "http://www.cvedetails.com/version-search.php?vendor={vendor}&product={product}&version={version}"

    def __init__(self, **kwargs):
        self.result = None
        self.g = grab.Grab(timeout=5, connect_timeout=5, user_agent='METASCAN')
        page_type = self.determine_page_type(self.search_url.format(**kwargs))
        logger.info(page_type)
        if page_type == 'error':
            self.result = None
        elif page_type == 'search_page':
            self.search_page(**kwargs)
            self.result = self.make_json_from_page()
        elif page_type == 'vulns_page':
            self.vulns_page()
            self.result = self.make_json_from_page()

    def get_references_from_cve_page(self, cve_id):
        cve_url = "http://www.cvedetails.com/cve/" + cve_id
        cve_object = grab.Grab()
        cve_object.go(cve_url)
        references_table = cve_object.doc.select('//tr/td/a[@title="External url"]')[:]
        return [reference.text() for reference in references_table]

    def make_json_from_page(self):
        result_map = {}
        # result_map['CVES'] = []
        rows_in_table = len(self.g.doc.select('//table/tr')[12::2])
        # Описание полей и описание CVE идут отдельно строкой, поэтому шаг = 2
        # Вся магия основана на анализе html
        header = self.g.doc.select('//table/tr/th')[3:]
        for row_number in range(rows_in_table):
            row = self.g.doc.select('//table/tr/td')[9 + row_number * 16:]
            descr = self.g.doc.select('//table/tr/td')[24 + row_number * 16:]
            # В каждой строчке 16 полей, смещаемся каждый раз на 1 строку.
            row_map = {'Exploits': None}
            for i, field in enumerate(header):
                column_name = normalize_string(field.text())
                if column_name:
                    row_map[column_name] = row[i].text()
            row_map['Text'] = descr[0].text()
            try:
                cve_id = row_map['CVEID']
                if cve_id:
                    row_map['references'] = self.get_references_from_cve_page(cve_id)
            except Exception as e:
                logger.warning("SOMETHING GONE WRONG")
                raise e
            # result_map['CVES'].append(row_map['CVE ID']) Если понадобится список всех CVE отдельным листом
            result_map[cve_id] = row_map
        return result_map

    def determine_page_type(self, url):
        logger.info(url)
        try:
            self.g.go(url)
        except grab.error.GrabCouldNotResolveHostError as e:
            logger.critical('Cant fetch {0} with error {1}'.format(url, e))
            return "error"
        table_header = self.g.doc.select('//td/div/h1').text()
        error = self.g.doc.text_search(u'No matches')
        if error:
            return "error"
        elif table_header == "Vendor, Product and Version Search":
            return "search_page"
        elif "Vulnerabilities" in table_header:
            return "vulns_page"
        else:
            return "error"

    def search_page(self, vendor, product, version, patch):
        rows_in_table = len(self.g.doc.select('//table[@class="searchresults"]/tr'))-1
        for row_number in range(rows_in_table):
            patch_from_html = self.g.doc.select('//table[@class="searchresults"]/tr/td')[5 + row_number * 9:][0]
            version_link_raw = self.g.doc.select('//table[@class="searchresults"]/tr/td')[8 + row_number * 9:][0].html()
            version_link = version_link_raw.split("\"")[5]
            if patch_from_html.text() == patch:
                try:
                    patch_url = "http://www.cvedetails.com" + version_link
                    self.g.go(patch_url)
                    break
                except Exception as e:
                    logging.critical('Cant fetch {0} with error {1}'.format(patch_url, e))
            else:
                raise RuntimeError('Cant find match for {0}:{1}:{2}:{3}'.format(vendor, product, version, patch))

    def vulns_page(self):
        html_with_pages_links = self.g.doc.select('//div[@class="paging"]/a')[:]
        pages_links = [link.html().split(" ")[1] for link in html_with_pages_links]
        for page in pages_links:
            try:
                self.g.go(page)
            except Exception as e:
                logging.warning('Cant fetch {0} with error {1}'.format(page, e))


if __name__ == '__main__':
    args = args_parser.parse_args()
    client = CVEDetailsClient(**vars(args))
    for _, v in client.result.items():
        print("{CVEID} TYPE: {VulnerabilityTypes}, SCORE: {Score}, PUBLISHED: {PublishDate} \nEXPLOITS: {Exploits}\n{Text} \n".format(**v))
