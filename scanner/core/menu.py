import os
import sys
from enum import Enum
import crayons
from scanner.core.scanner import Scanner


class ScanOption(Enum):
    fullWithHtml = 1
    fastWithHtml = 2
    fullWithoutHtml = 3
    fastWithoutHtml = 4
    exitScan = 5


class Menu:
    def __init__(self):
        self.banner = """\
__   __  _____  _____    _____                                   
\ \ / / / ____|/ ____|  / ____|                                      
 \ V / | (___ | (___   | (___    ___  __ _  _ __   _ __    ___  _ __ 
  > <   \___ \ \___ \   \___ \  / __|/ _` || '_ \ | '_ \  / _ \| '__|
 / . \  ____) |____) |  ____) || (__| (_| || | | || | | ||  __/| |   
/_/ \_\|_____/|_____/  |_____/  \___|\__,_||_| |_||_| |_| \___||_|   
                                                                        
            Created by @BondocClaudiu | https://github.com/BondocClaudiu/XSS-Scanner"""
        self.menu = """\
    [1] Scan URL (Full with HTML Scan)

    [2] Scan URL (Fast with HTML Scan)

    [3] Scan URL (Full without HTML Scan)

    [4] Scan URL (Fast without HTML Scan)
    
    [5] Exit Program\n"""

    def open(self):
        stop_on_first = False
        store_output = False
        report_out = None
        cookies = None
        url = None
        fastPayload = False
        htmlScan = False
        headlessBrowser = False

        print(crayons.blue(self.banner))
        print('\nWelcome to XSS Scanner. Choose one of the following options:\n')
        print(self.menu)
        if 'win32' in sys.platform or 'win64' in sys.platform:
            ps1 = str('xss_scanner> ')
        else:
            ps1 = str(crayons.blue(
                '[') + crayons.white('xss_scanner') + crayons.blue(']') + '> ')

        while True:
            scanOption = int(input(ps1))

            if(scanOption not in [opt.value for opt in ScanOption]):
                print(crayons.red('\nUnknown Option. Please Choose a valid one\n'))
            else:

                if(scanOption == ScanOption.fullWithHtml.value):
                    htmlScan = True
                elif(scanOption == ScanOption.fastWithHtml.value):
                    htmlScan = True
                    fastPayload = True
                elif(scanOption == ScanOption.fullWithoutHtml.value):
                    pass
                elif(scanOption == ScanOption.fastWithoutHtml.value):
                    fastPayload = True
                elif(scanOption == ScanOption.exitScan.value):
                    os._exit(0)

                print('\nPlease enter URL to scan w/ parameters included:')
                print(
                    crayons.green('[ex.]'), 'https://xss-game.appspot.com/level1/frame?query=test\n')
                url = input(ps1)

                print(
                    '\nWould you like to open the browser in order to see the actual testing?')
                while True:
                    ans = self.getYorN()
                    if ans == 'n':
                        headlessBrowser = True
                        break
                    elif ans == 'y':
                        headlessBrowser = False
                        break
                    else:
                        self.printUnknownOption()

                print('\nWould you like to add some cookies?')
                while True:
                    ans = self.getYorN()
                    if ans == 'n':
                        cookies = None
                        break
                    elif ans == 'y':
                        print('Please enter your cookies strings in this format:')
                        print(crayons.green(
                            '[ex.]'), '<cookiename>:<cookievalue>:<cookiepath>,<cookiename>:<cookievalue>:<cookiepath>\n')
                        cookies = input(ps1)
                        break
                    else:
                        self.printUnknownOption()

                print('\nWould you like to stop after the first vulnerability found?')
                while True:
                    ans = self.getYorN()
                    if ans == 'n':
                        stop_on_first = False
                        break
                    elif ans == 'y':
                        stop_on_first = True
                        break
                    else:
                        self.printUnknownOption()

                print('\nWould you like to store the results in a JSON file?')
                while True:
                    ans = self.getYorN()
                    if ans == 'n':
                        store_output = False
                        report_out = None
                        break
                    elif ans == 'y':
                        store_output = True
                        print('\nPlease enter the file name below:\n')
                        report_out = input(ps1)
                        break
                    else:
                        self.printUnknownOption()

                print(
                    crayons.red('[*] This may take a while. Press ENTER to continue or Ctrl-C to quit.. [*]'))
                input()
                print()
                scanner = Scanner(url, cookies, stop_on_first, store_output, report_out,
                                  html_scan=htmlScan, fast_payload=fastPayload, headlessBrowser=headlessBrowser)
                scanner.run()
                scanner.store_results()

    def printUnknownOption(self):
        print(crayons.red('\nUnknown option. Please choose Y or N.\n'))

    def getYorN(self) -> str:
        return input('\n[Y\\n]> ').lower()
