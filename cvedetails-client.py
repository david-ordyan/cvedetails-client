#!/usr/bin/env python3
import grab, re, logging, sys

logger = logging.getLogger(__name__)

class CVEdetailsClient:
    def normalize_string(self, string):
        if type(string) is str:
            return re.sub('[^a-zA-Z0-9]','',string)

    def get_references_from_cve_page(self, cve_id):
        link_to_cve_page = "http://www.cvedetails.com/cve/" + cve_id
        references = []
        cve_object = grab.Grab()
        cve_object.go(link_to_cve_page)
        references_table = cve_object.doc.select('//tr/td/a[@title="External url"]')[:]
        for reference in references_table:
            references.append(reference.text())
        return references

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
            row_map = {}
            for column in range(len(header)):
                column_name = re.sub('[^a-zA-Z0-9]','', header[column].text())
                if column_name:
                    row_map[self.normalize_string(column_name)] = row[column].text()
            row_map['text'] = descr[0].text()
            try:
                cve_id = row_map['CVEID']
                if cve_id:
                    row_map['references'] = self.get_references_from_cve_page(cve_id)
            except Exception as e:
                logger.warning("SOMETHING GO WRONG")
                raise e
            # result_map['CVES'].append(row_map['CVE ID']) Если понадобится список всех CVE отдельным листом
            result_map[cve_id] = row_map
        return result_map

    def determine_page_type(self):
        try:
            self.g.go(self.cvedetails_url)
        except grab.error.GrabCouldNotResolveHostError as e:
            logger.critical('Cant fetch {0} with error {1}'.format(self.cvedetails_url, e))
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

    def search_page(self):
        logger.info(self.cvedetails_url)
        rows_in_table = len(self.g.doc.select('//table[@class="searchresults"]/tr')[1:])
        for row_number in range(rows_in_table):
            patch_from_html = self.g.doc.select('//table[@class="searchresults"]/tr/td')[5 + row_number * 9:][0]
            version_link_raw = self.g.doc.select('//table[@class="searchresults"]/tr/td')[8 + row_number * 9:][0].html()
            version_link = version_link_raw.split("\"")[5]
            if patch_from_html.text() == self.patch:
                try:
                    self.cvedetails_url = "http://www.cvedetails.com" + version_link
                    self.g.go(self.cvedetails_url)
                    break
                except Exception as e:
                    logging.critical('Cant fetch {0} with error {1}'.format(self.cvedetails_url, e))
                    pass
            else:
                logging.warning('Cant find match for {0}:{1}:{2}:{3}'.format(self.vendor, self.product , self.version, self.patch,))

    def vulns_page(self):
        logger.info(self.cvedetails_url)
        html_with_pages_links = self.g.doc.select('//div[@class="paging"]/a')[:]
        pages_links = [(link.html().split(" ")[1]) for link in html_with_pages_links]
        for page in pages_links:
            try:
                self.g.go(page)
            except Exception as e:
                logging.warning('Cant fetch {0} with error {1}'.format(page, e))
                pass

    def __init__(self, vendor, product, version, patch):
        self.result = None
        self.g = grab.Grab(timeout=5, connect_timeout=5, user_agent='METASCAN')
        self.vendor = vendor
        self.patch = patch
        self.product = product
        self.version = version
        if self.vendor and self.product and self.version:
            self.cvedetails_url = "http://www.cvedetails.com/version-search.php?vendor=" + self.vendor + "&product=" + product + "&version=" + version
            page_type = self.determine_page_type()
            logger.ifno(page_type)
            if page_type == 'error':
                self.result = None
            elif page_type == 'search_page':
                self.search_page()
                self.result = self.make_json_from_page()
            elif page_type == 'vulns_page':
                self.vulns_page()
                self.result = self.make_json_from_page()

if __name__ == '__main__':
    try:
        vendor, product, version, patch = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    except:
        print('Usage: {0} {1}'.format(sys.argv[0], 'vendor product version patch'))
        sys.exit(-1)
    client = CVEdetailsClient(vendor, product, version, patch)
    for key in client.result.keys():
        print("{0} TYPE: {1}, SCORE: {2}, PUBLISHED: {3} \nEXPLOITS: {4}\n{5} \n".format(client.result[key]['CVEID'],client.result[key]['VulnerabilityTypes'],client.result[key]['Score'],client.result[key]['PublishDate'],client.result[key].get('Exploits'),client.result[key]['text']))
