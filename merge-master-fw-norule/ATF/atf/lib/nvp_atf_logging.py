#
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
#

"""
This is a default logging framework defined for OC ATF.
"""

import logging
import datetime
# import sys
import os
# sys.path.append("../../")

import atf.config.common_config as config


def get_atf_logger():
    """This returns the _LOGGER object needed to log the messages."""
    return _LOGGER


def create_log_dir():
    """It creates the log directory"""
    # Create the log dir, if not created previously.
    if not os.path.exists(config.atf_log_path):
        os.system("mkdir -p " + config.atf_log_path)


def get_log_file_abs_path():
    return ABS_FILE_PATH


def set_log_file(file_name):
    """This sets the new log file for the log messages.
    param:
        file_name: name of the new log file
    """
    global FILE_HANDLER
    # Remove the existing handler.
    _LOGGER.removeHandler(FILE_HANDLER)
    # Create the new handler with the new file.
    file_frmt = ""
    if ".log" not in file_name:
        file_frmt = ".log"
    file_path = config.atf_log_path + file_name + file_frmt

    FILE_HANDLER = logging.FileHandler(file_path)
    FILE_HANDLER.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] [%(filename)s]'
        ' [%(funcName)s] [%(threadName)s] %(message)s')
    FILE_HANDLER.setFormatter(formatter)
    _LOGGER.addHandler(FILE_HANDLER)

# NOT required, but is a good way to put the global things inside.
if __name__:

    NOW = str(datetime.datetime.now().strftime('%Y%b%d_%Hh%Mm%Ss')).strip()
    ABS_FILE_PATH = config.atf_log_path + config.atf_log_file_name + \
        "_" + NOW + ".log"
    # Create log dir, if not created.
    create_log_dir()

    # Get _LOGGER object.
    _LOGGER = logging.getLogger(__name__)

    # Set the default level as DEBUG
    _LOGGER.setLevel(logging.DEBUG)

    # Get the File handler object to redirect the log messages to a file.
    FILE_HANDLER = logging.FileHandler(ABS_FILE_PATH)
    FILE_HANDLER.setLevel(logging.DEBUG)

    # Get the Formatter object to specify the logging formats.
    FORMATTER = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] [%(filename)s] '
        ' [%(funcName)s] [%(threadName)s] %(message)s')
    # Set the FORMATTER to the file handler.
    FILE_HANDLER.setFormatter(FORMATTER)
    # Add this file handler to the _LOGGER object.
    _LOGGER.addHandler(FILE_HANDLER)
