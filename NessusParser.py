"""Parses Nessus CSV files. Can compares the result of two Nessus CSV files or a previous file made with this tool to
determine fixed issues and new issues. In order to run this xlrx and xlswriter must be installed: pip install xlrd
xlsxwriter. Usage of the script is: python NessusParser.py -h """
import csv
import argparse
import xlsxwriter
import xlrd
import time
from datetime import datetime


# The class is a bit redundant, as the program/scripts does not make use of custom objects
class NessusParser:

    def __init__(self):
        # Parameters used for parsing arguments
        description = "Parses Nessus CSV files. Can compares the result of two Nessus CSV files or a previous file " \
                      "made with " \
                      "this tool to determine fixed issues and new issues. In order to run this, xlrx and xlswriter " \
                      "must be " \
                      "installed: pip install xlrd xlsxwriter "
        parser = argparse.ArgumentParser(description=description)
        parser.add_argument("-new", metavar="new.csv", help="The new or current csv files", nargs="+")
        parser.add_argument("-old", metavar="old.csv", help="The old csv files", nargs="+")
        parser.add_argument("-excel", metavar="old.xlsx", help="The previous excel files")
        parser.add_argument("-info", help="also process informational/none issues", action="store_true")
        parser.add_argument("-check",
                            help="check if there are new systems or disappeared systems since the previous scan. "
                                 "Only works when the csv or old excel file contains informational/none isses",
                            action="store_true")
        self.args = parser.parse_args()
        # Parameters used for writing the results
        self.current_time = datetime.utcfromtimestamp(time.time()).strftime("%Y%m%d")
        self.workbook = xlsxwriter.Workbook("NessusResults_" + self.current_time + ".xlsx")
        self.latestResults = []
        self.latestHosts = set()
        self.previousResults = []
        self.previousHosts = set()
        warning = ("Note:",
                   " False positives that were manually removed from current scan results are included in the table "
                   "below",)
        column = tuple(("CVSS", "Risk", "Host IP", "FQDN", "Additional DNS names", "Protocol", "Port", "Name"))
        self.newResults = []
        self.newResults.append(warning)
        self.newResults.append(column)
        self.fixedResults = []
        self.fixedResults.append(warning)
        self.fixedResults.append(column)
        self.hostOverview = []
        self.newHosts = []
        self.disappearedHosts = []

    # Starts parsing the results
    def start_parsing(self):
        if self.args.new:
            self.latestResults = self.parser(self.args.new)
            self.write_sheet(self.latestResults, "Current scan results")
        else:
            self.workbook.close()
            print("No new csv files specified, so I'm not doing anything. Use -h to show some options")
            exit()
        if self.args.old:
            self.previousResults = self.parser(self.args.old)
            self.write_sheet(self.previousResults, "Previous scan results")
            self.compare()
            if self.args.check:
                self.check()
        if self.args.excel:
            if '.xlsx' in self.args.excel[:]:
                row_number = 2
                excel_file = self.args.excel[:]
                previous_workbook = xlrd.open_workbook(excel_file)
                previous_worksheet = previous_workbook.sheet_by_name("Current scan results")
                while row_number < previous_worksheet.nrows:
                    row = previous_worksheet.row_values(row_number, 2, 10)
                    self.previousResults.append(tuple(row))
                    row_number += 1
                self.write_sheet(self.previousResults, "Previous scan results")
                self.compare()
                if self.args.check:
                    self.check()
        self.workbook.close()

    def parser(self, arguments):
        result_list = []
        host_mapping = {}
        temp_latest = []
        for argument in arguments:
            with open(str(argument), encoding="utf8") as csvfile:
                reader = csv.reader(csvfile, delimiter=",")
                for row in reader:
                    # Filters out rows for which the fourth value is the string "Host"
                    if row[4] != "Host":
                        # Checks if the fourth value of the row, which is an IP addresss, is in the host_mapping
                        # dictionary. If
                        # not, a new host object is created with that IP
                        if row[4] not in host_mapping:
                            host = Host(row[4])
                            host_mapping[row[4]] = host
                        # Checks for the plugin that resolves the name of the host
                        if row[0] == "12053":
                            plugin_output = row[12].split()
                            # Creates a mapping of IP addresses and hostnames
                            host = host_mapping[row[4]]
                            host.set_fqdn(plugin_output[3][:-1] + " " + host.get_fqdn())
                            host_mapping[row[4]] = host
                        # Checks for the plugin that resolves additional DNS hostnames
                        if row[0] == "46180":
                            plugin_output = row[12].split()
                            # Creates a mapping of IP addresses and hostnames
                            host = host_mapping[row[4]]
                            host.set_dns(plugin_output[10] + " " + host.get_dns())
                            host_mapping[row[4]] = host
                    result = (row[2:8])
                    if result not in temp_latest:
                        temp_latest.append(result)
            for row in temp_latest:
                result = tuple(row)
                # If statement solely for the headers in order to split them correctly
                if result[2] == "Host":
                    result = result[:2] + ("Host IP", "FQDN", "Additional DNS names") + result[3:]
                for host in host_mapping:
                    if row[2] == host:
                        result = (result[:3] + (
                            host_mapping[host].get_fqdn(), host_mapping[host].get_dns()) + result[3:])
                if result not in result_list:
                    result_list.append(result)
        return result_list

    # Performs checks on the latest and previous scans to determine the deltas in regard to the found vulnerabilities
    def compare(self):
        self.newResults.extend(set(tuple(self.latestResults)) - set(tuple(self.previousResults)))
        self.fixedResults.extend((set(tuple(self.previousResults)) - set(tuple(self.latestResults))))
        self.write_sheet(self.newResults, "New issues")
        self.write_sheet(self.fixedResults, "Fixed issues")

    # Performs checks on the latest and previous scans to determine the deltas in regard to the number of hosts
    def check(self):
        temp_new = set()
        temp_old = set()
        for result in self.latestResults:
            temp_new.add((result[2], result[3], result[4]))
            host_overview = (result[2], result[3], result[4])
            if host_overview not in self.hostOverview:
                self.hostOverview.append(host_overview)
        for result in self.previousResults:
            temp_old.add((result[2], result[3], result[4]))
        self.newHosts.append(("Host IP", "FQDN", "Additional DNS names"))
        self.newHosts.extend((set(tuple(temp_new)) - set(tuple(temp_old))))
        self.disappearedHosts.append(("Host IP", "FQDN", "Additional DNS names"))
        self.disappearedHosts.extend((set(tuple(temp_old)) - set(tuple(temp_new))))
        self.write_sheet(self.hostOverview, "Host overview")
        self.write_sheet(self.newHosts, "New hosts")
        self.write_sheet(self.disappearedHosts, "Disappeared hosts")

        # Writes sheet

    def write_sheet(self, result_list, sheet_name):
        worksheet = self.workbook.add_worksheet(sheet_name)
        row_number = 3
        for result in result_list:
            if not self.args.info:
                if result[1] != "None":
                    worksheet.write_row("C" + str(row_number), result)
                    row_number += 1
            else:
                worksheet.write_row("C" + str(row_number), result)
                row_number += 1


# Host have an IP address, a FQDN and maybe additional DNS names. Creating an object solves a lot.
class Host:

    def __init__(self, ip):
        self.ip = ip
        self.fqdn = ""
        self.dns = ""

    def get_ip(self):
        return self.ip

    def set_ip(self, ip):
        self.ip = ip

    def get_fqdn(self):
        return self.fqdn

    def set_fqdn(self, fqdn):
        self.fqdn = fqdn

    def get_dns(self):
        return self.dns

    def set_dns(self, dns):
        self.dns = dns


# Main method for program/script
def main():
    parse = NessusParser()
    parse.start_parsing()


# Calls main method
if __name__ == '__main__':
    main()
