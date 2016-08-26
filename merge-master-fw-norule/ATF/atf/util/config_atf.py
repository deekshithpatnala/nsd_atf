# One Convergence, Inc. CONFIDENTIAL
# Copyright (c) 2012-2014, One Convergence, Inc., USA
# All Rights Reserved.
#
# All information contained herein is, and remains the property of
# One Convergence, Inc. and its suppliers, if any. The intellectual and
# technical concepts contained herein are proprietary to One Convergence,
# Inc. and its suppliers.
#
# Dissemination of this information or reproduction of this material is
# strictly forbidden unless prior written permission is obtained from
# One Convergence, Inc., USA

"""This module is for updating the config files"""

import json
import os
import shutil
import sys

sys.path.append("../../")
import atf.config.setup_config as setup
import atf.config.common_config as comconfig
from atf.util import ini2json


class ConfigAtf(object):
    """
    This class updates the configuration files such as common_config
    and setup_config.
    """
    def __init__(self, ini_file_path):
        self.setup = setup
        self.comconfig = comconfig
        self.ini2json = ini2json.StrictConfigParser()
        self.in_file_json = self.ini2json.get_json_from_ini(ini_file_path)

    def update_setup_config(self, setup_file):
        """
        This method updates the input setup_file from an input ini file.
        """
        with open(self.in_file_json) as data_file:
            data = json.load(data_file)
            modified_list = set()
            for val in data.keys():
                if (val.lower() in self.setup.setupInfo.keys()) or \
                   (val[:-2].lower() in self.setup.setupInfo.keys()):
                    if val[:-2].lower() in self.setup.setupInfo.keys():
                        sval = val[:-2]
                        if sval not in modified_list:
                            self.setup.setupInfo[sval.lower()] = []
                            modified_list.add(sval)
                        self.setup.setupInfo[sval.lower()].append(data[val])
                        continue
                    for ikey in data[val].keys():
                        if ikey.lower() in \
                           self.setup.setupInfo[val.lower()].keys():
                            self.setup.setupInfo[val.lower()][ikey.lower()] = \
                             data[val][ikey]
        out_file = open(setup_file, 'w')
        out_file.write("setupInfo = " + json.dumps(setup.setupInfo,
                                                   indent=16, sort_keys=True))
        out_file.close()
        self.prepend_licence(setup_file)  # to prepend licence

    def prepend_licence(self, filename):
        """This method is to prepend licence text to a file"""
        licence_file_name = os.path.basename(__file__)
        lic_file = open(licence_file_name)
        filetoprepend = filename + "_new"
        out_file = open(filetoprepend, 'w')
        count_lines = 14  # number of licence text in this file.
        for line in lic_file:
            if count_lines >= 0:
                out_file.write(line)
                count_lines -= 1
            else:
                break

        out_file.close()

        in_file = open(filename)
        out_file = open(filetoprepend, 'a')
        for line in in_file:
            out_file.write(line)
        out_file.close()
        in_file.close()
        shutil.move(filetoprepend, filename)

    def update_common_config(self, commonconfig_file):
        """This method updates input common_config file from input ini file"""
        modified_list = set()
        out_list = []
        out_dict = {}
        config_dict = self.comconfig.__dict__
        with open(self.in_file_json) as data_file:
            data = json.load(data_file)
            for val in data.keys():
                sval = val.replace("-", "_")
                sval = sval.lower()
                if sval in config_dict.keys():
                    if isinstance(data[val], dict):
                        out_dict[sval] = data[val]
                    else:
                        out_str = sval + " = \"" + data[val] + "\""
                        out_list.append(out_str)
                    del config_dict[sval]
                elif sval[:-2] in config_dict.keys():
                    sval = sval[:-2]
                    if sval not in modified_list:
                        out_dict[sval] = []
                        modified_list.add(sval)
                    out_dict[sval].append(data[val])
                else:
                    for ikey in data[val].keys():
                        if ikey in config_dict.keys():
                            out_str = ikey + " = \"" + data[val][ikey] + "\""
                            out_list.append(out_str)
                            del config_dict[ikey]
                        else:
                            pass
        for item in modified_list:
            del config_dict[item]
        out_file = open(commonconfig_file, "w")
        for item in out_list:
            out_file.write(item + "\n\n")
        for item in out_dict.keys():
            if isinstance(out_dict[item], list):
                out_file.write(item + " = " + "[")
                last = len(out_dict[item]) - 1
                for flag, dic in enumerate(out_dict[item]):
                    if isinstance(dic, dict):
                        out_file.write("{\n")
                        last2 = len(dic.keys()) - 1
                        for flag2, key in enumerate(dic.keys()):
                            out_file.write("\t\t\t\"" + key + "\" : \"" +
                                           dic[key] + "\"")
                            if flag2 != last2:
                                out_file.write(",\n")
                            else:
                                out_file.write("\n")
                    if flag != last:
                        out_file.write("\t\t\t},")
                    else:
                        out_file.write("\t\t\t}")
                out_file.write("]\n")
            else:
                out_file.write(item + " = " + "{\n")
                last = len(out_dict[item].keys()) - 1
                for flag, key in enumerate(out_dict[item].keys()):
                    out_file.write("\t\t\t\"" + key + "\" : \"" +
                                   out_dict[item][key] + "\"")
                    if flag != last:
                        out_file.write(",\n")
                    else:
                        out_file.write("\n")
                out_file.write("}\n")
        for item in config_dict.keys():
            if item.startswith("_"):
                pass
            else:
                if isinstance(config_dict[item], bool):
                    out_file.write(item + " = " + str(config_dict[item]) +
                                   "\n\n")
                elif isinstance(config_dict[item], dict):
                    put_str = str(config_dict[item])
                    # print put_str
                    out_file.write(item + " = " + str(config_dict[item]) +
                                   "\n\n")
                elif isinstance(config_dict[item], list):
                    put_str = str(config_dict[item])
                    # print put_str
                    out_file.write(item + " = " + put_str + "\n\n")
                else:
                    out_file.write(item + " = \"" + str(config_dict[item]) +
                                   "\"\n\n")
        out_file.close()
        self.prepend_licence(commonconfig_file)  # to prepend license

ATF_CONF = ConfigAtf("../config/atf-config.ini")
ATF_CONF.update_setup_config("../config/setup_config.py")
ATF_CONF.update_common_config("../config/common_config.py")
