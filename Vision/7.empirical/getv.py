import json
import time

import requests
from lxml import etree
from playwright.sync_api import sync_playwright


def get_versions_from_html(html_path) -> tuple[dict, list]:
    version_list = []
    major_version_list = {}
    with open(html_path, 'r') as f:
        html = etree.HTML(f.read(), parser=None)
        tr_list = list(html.xpath("//div[@class='tab_container']//table/tbody/tr"))
        i = 0
        while i < len(tr_list):
            tr_element = tr_list[i]
            try:
                cnt = int(tr_element.xpath("td[1]/@rowspan")[0])
                version = tr_element.xpath("td[2]/a/text()")[0]
                version_list.append(version)
                major_version = tr_element.xpath("td[1]/div//b/text()")[0] + tr_element.xpath("td[1]/div/text()")[0]
                major_version_list[major_version] = [version]

                j = i + 1
                while j < i + cnt:
                    tr_element = tr_list[j]
                    version = tr_element.xpath("td[1]/a/text()")[0]
                    version_list.append(version)
                    major_version_list[major_version].append(version)
                    j += 1
                i += cnt
            except Exception as e:
                version = tr_element.xpath('td[1]/a/text()')[0]
                version_list.append(version)
                i += 1

    return major_version_list, version_list

with open("cve_gav_all_overlap_generality.json") as f:
    data = json.load(f)

for cveid, ga in data.items():
    g = ga.split("/")[0]
    a = ga.split("/")[1]
    maven_url = f"https://search.maven.org/solrsearch/select?q=g:{g}+AND+a:{a}&core=gav"
    res = requests.get(maven_url)
    with open(f"{cveid}.json", "w") as f:
        json.dump(res.json(), f)
    time.sleep(10)
