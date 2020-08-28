import json
import urllib
import os
import datetime
import crayons
from selenium import webdriver
from selenium.common.exceptions import (ElementNotInteractableException, NoSuchElementException,
                                        StaleElementReferenceException, TimeoutException, UnexpectedAlertPresentException)
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions

from scanner.core.helper import *


class Scanner:
    def __init__(self, url, cookies=None, stop_on_first=False, store_report=False,
                 report_output=None, fast_payload=False, html_scan=False, headlessBrowser=False):
        self.payloads = get_payloads_from_vectors(fast_payload)
        self.url = url
        self.stop_on_first = stop_on_first
        self.base_url = get_base_url(self.url)
        self.params = get_params(self.url)
        self.html_scan = html_scan
        self.cookies = cookies
        if cookies:
            self.cookies = get_cookies(cookies)
        self.result_count = 0
        self.results = {
            'targetUrl': self.url,
            'startScanTimeStamp': get_date_time_as_string(datetime.datetime.now()),
            'endScanTimeStamp': None,
            'results': []
        }
        self.store_report = store_report
        self.report_output = report_output
        self.web_elements = None
        self.is_headless_driver = headlessBrowser
        if store_report:
            if not report_output:
                raise Exception('Missing Report Output')

    def run(self):
        print(crayons.blue('[*] Running XSS Scan [*]'))
        options = webdriver.ChromeOptions()

        if(self.is_headless_driver):
            options.add_argument('--headless')
        self.driver = webdriver.Chrome(chrome_options=options)
        window = self.setup_window()

        try:
            self.driver.switch_to.window(window)

            # First try query scan
            print(crayons.blue("Starting query scan!"))

            if(len(self.params.keys()) == 0):
                print(crayons.red("Cannot find query params!"))
            else:
                for count, payload in enumerate(self.payloads, start=1):
                    print_payload_count(count, self.payloads)
                    self.query_scanner(payload)

            # Then html scan,if present
            if self.html_scan:
                print(crayons.blue("Starting html scan!"))
                self.refresh_page()

                self.web_elements = self.get_web_elements()
                for count, payload in enumerate(self.payloads, start=1):
                    print_payload_count(count, self.payloads)
                    self.html_scanner(payload, len(
                        self.web_elements), self.base_url)
        except TimeoutException as err:
            print_error_message(
                'Timeout error !!!', 'None at this stage!', None, err)
        except KeyboardInterrupt:
            print(crayons.blue('Scan closed by user. Saving the partial results ...'))
            self.final_report()

        self.final_report()

    def query_scanner(self, payload):
        for param in self.params.keys():
            self.params[param] = payload
            target_url = encode_url(self.base_url, self.params)
            self.raw_params = urllib.parse.urlencode(self.params)

            self.driver.get(target_url)
            try:
                isAlertPresent = expected_conditions.alert_is_present()
                WebDriverWait(self.driver, 3).until(isAlertPresent)

                if(isAlertPresent):
                    self.handle_alert()
                    self.add_result(self.raw_params, target_url, "URL Query")

            except TimeoutException:
                print("Timeout on payload: " + payload)
            except UnexpectedAlertPresentException as err:
                print_error_message(
                    'An alert is already present due to race-conditions or unproper handling :)', payload, err)
                self.handle_alert()
            finally:
                self.refresh_page()

    def html_scanner(self, payload, web_elements_len, target_url):
        for elem_index in range(web_elements_len):
            try:
                element = self.web_elements[elem_index]
                if element.tag_name == 'input' or element.tag_name == 'textarea':
                    element.send_keys(payload)
                    element.submit()

                    isAlertPresent = expected_conditions.alert_is_present()
                    WebDriverWait(self.driver, 3).until(isAlertPresent)

                    if(isAlertPresent):
                        self.handle_alert()
                        self.add_result(payload, target_url, "HTML Injection")

            except TimeoutException as err:
                print("Timeout on payload: " + payload)
            except StaleElementReferenceException as err:
                print_error_message(
                    'The Webdriver did not find the element in DOM!', payload, err)
            except ElementNotInteractableException as err:
                print_error_message(
                    'The Webdriver could not interact with the element in DOM!', payload, err)
            except UnexpectedAlertPresentException as err:
                print_error_message(
                    'An alert is already present due to race-conditions or unproper handling :)', payload, err)
                self.handle_alert()
            except NoSuchElementException as err:
                print_error_message(
                    'Cannot find web element', payload, err)
            finally:
                self.refresh_page_and_web_elements()

    def setup_window(self):
        window = self.driver.current_window_handle

        if self.cookies:
            self.driver.get(self.url)
            addCookiesToWebDriver(self.driver, self.cookies)
        self.refresh_page()

        return window

    def refresh_page(self):
        repeat_refreshing = True

        while True:
            try:
                if(not repeat_refreshing):
                    break

                self.driver.get(self.base_url)

            except UnexpectedAlertPresentException as err:
                print_error_message(
                    'An alert is present at {method_name} level. Trying to scan the DOM again ... :)'
                    .format(method_name=self.refresh_page.__name__), None, err)
                self.handle_alert()
                repeat_refreshing = True
            else:
                repeat_refreshing = False

    def refresh_page_and_web_elements(self):
        self.refresh_page()
        self.web_elements = self.get_web_elements()

    def handle_alert(self):
        try:
            WebDriverWait(self.driver, 2).until(expected_conditions.alert_is_present(),
                                                'Timed out waiting for PA creation ' +
                                                'confirmation popup to appear.')

            alert = self.driver.switch_to.alert
            alert.dismiss()
            print("---alert dismissed---")
        except TimeoutException:
            print("---no alert---")
        except UnexpectedAlertPresentException as err:
            self.handle_alert()

    def get_web_elements(self):

        repeat_scanning = True
        webelement_list = []

        while True:
            try:
                if(not repeat_scanning):
                    break

                # Querying the DOM for inputs
                webelement_list = WebDriverWait(self.driver, 10).until(
                    expected_conditions.presence_of_all_elements_located((By.XPATH, "//input | //textarea")))

                webelement_list = list(
                    filter(filter_inputs_by_type, webelement_list))

            except UnexpectedAlertPresentException as err:
                print_error_message(
                    'An alert is present at {method_name} level. Trying to scan the DOM again ... :)'
                    .format(method_name=self.refresh_page.__name__), None, err)
                self.handle_alert()
                repeat_scanning = True
            else:
                repeat_scanning = False

        return webelement_list

    def add_result(self, raw_params, target_url, scan_type):
        self.result_count += 1

        print(crayons.green('RESULTS: {}'.format(
            self.result_count).center(50, '='), bold=True))
        print()
        print(crayons.blue('[') + crayons.green('*', bold=True) + crayons.blue(']') +
              crayons.green(' Found XSS Vulnerability'))
        print(crayons.blue('[') + crayons.green('*', bold=True) + crayons.blue(']') +
              crayons.green(' Scan Type:'), crayons.blue(scan_type))
        print(crayons.blue('[') + crayons.green('*', bold=True) + crayons.blue(']') +
              crayons.green(' Payload:'), crayons.blue(raw_params))
        print(crayons.blue('[') + crayons.green('*', bold=True) + crayons.blue(']') +
              crayons.green(' URL:'), crayons.blue(target_url))
        print()
        print(crayons.green(''.center(50, '='), bold=True))

        self.results['results'].append({
            'count': self.result_count,
            'scanType': scan_type,
            'payload': raw_params,
            'url': target_url
        })

        if self.stop_on_first:
            self.driver.quit()
            self.final_report()

    def store_results(self):
        if self.store_report:
            if not self.report_output.endswith('.json'):
                report_out = self.report_output + '.json'
                real_path = os.path.realpath(report_out)
            else:
                real_path = os.path.realpath(self.report_output)
            if os.path.exists(real_path):
                os.remove(real_path)
            with open(real_path, 'w') as file:
                file.write('{}')
            with open(real_path, 'r+') as json_file:
                self.results['endScanTimeStamp'] = get_date_time_as_string(
                    datetime.datetime.now())
                obj = json.load(json_file)
                obj = self.results
                json_file.truncate()
                json_file.seek(0)
                json.dump(obj, json_file, indent=4)

            print(crayons.blue(
                '[*] Stored Results To {}'.format(real_path)))

    def final_report(self):
        print(crayons.blue('[*] Scan Completed'))
        if self.result_count == 0:
            print(crayons.red(
                '[!] No Results Found. Warning This Does NOT Mean You Are Not Still Vulnerable [!]'))
        else:
            print(crayons.green(
                'Found ' + str(self.result_count) + ' vulnerabiliti(es)!'))

            self.store_results()
        input("Press any key to exit.....")
        os._exit(0)
