import datetime
from typing import Dict, List
import urllib
from crayons import *


def get_payloads_from_vectors(fast=False) -> List[str]:
    payloads = []
    vectorsPath = 'scanner/core/constants/vectors.txt'
    fastVectorsPath = 'scanner/core/constants/fast_vectors.txt'

    with open(fastVectorsPath if fast else vectorsPath, 'r', encoding="utf-8") as vector_file:
        for vector in vector_file.readlines():
            payloads.append(vector)

    return payloads


def get_base_url(url: str) -> str:
    base_url = url.split('?')[0]
    return base_url


def get_params(url: str) -> dict:
    pure_url = urllib.parse.urlparse(url)
    query_string = pure_url.query
    params = dict(urllib.parse.parse_qsl(query_string))
    return params


def encode_url(url, params) -> str:
    params_encoded = urllib.parse.urlencode(params)
    full_url = url + "?" + params_encoded
    return full_url


def get_cookies(cookies: str) -> List[Dict]:
    result = []
    cookies_list = cookies.split(',')

    for cookie in cookies_list:
        cookie_parts = cookie.split(':')
        cookie_obj = {
            'name': cookie_parts[0],
            'value': cookie_parts[1],
            'path': cookie_parts[2]
        }
        result.append(cookie_obj)

    return result


def addCookiesToWebDriver(driver, cookies) -> None:
    for cookie in cookies:
        driver.add_cookie(cookie)


def filter_inputs_by_type(web_element) -> bool:
    input_blackList_Types = {"submit", "reset", "button", "file", "image"}

    if(web_element.tag_name == "input" and
       web_element.get_attribute("type") in input_blackList_Types):
        return False
    else:
        return True


def get_date_time_as_string(time_stamp) -> str:
    return time_stamp.strftime("%m/%d/%Y, %H:%M:%S")


def print_error_message(message: str, payload: str, err) -> None:
    print(red(message + ' Payload: ' + str(payload or '') + '\nError: ' + repr(err)))
