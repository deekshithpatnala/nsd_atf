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


"""Module contains classes and methods, stress testing by
running parallel insertions in several threads.
"""

import threading

from atf.config import gbp_config
from atf.lib.lib_common import commonLibrary, StressTestHelper
from atf.lib.nvp_atf_logging import get_atf_logger
from atf.src.service_insertion import InsertionTests
from atf.src.service_ha import ServicesHATest
from atf.src.multiple_chain import MultipleChain
from atf.src.gbp_cruds import GbpCrudsValidation

# pylint: disable=W0703
# pylint: disable=W1201

LOG_OBJ = get_atf_logger()


class StressTests(StressTestHelper):
    """Class contains methods, for stress testing by
    running parallel insertions in several threads.
    """
    def __init__(self):
        """This is the constructor for StressTests class.

        Instance Variables:

        * __e2e_scenario_tcs_range:  Stress test cases number list,
             for End to end scenario test.

        * __services_ha_tcs_range: Stress test cases number list,
             services HA tests.

        * __multichains_tcs_range: Stress test cases number list,
             for multiple chains tests.

        * __gbp_cruds_tcs_range: Stress test cases number list,
             for gbp  rest api validation tests.

        * __common_obj: commonLibrary class object.
        """
        StressTestHelper.__init__(self)

        def xmap_add(num, xlist):
            """Add number to every element of list"""
            return [x + num for x in xlist]

        self.__e2e_scenario_tcs_range =\
            range(1, gbp_config.MAX_INSERTION_TC_NO + 1)
        self.__services_ha_tcs_range = xmap_add(
                self.__e2e_scenario_tcs_range[-1],
                range(1, gbp_config.MAX_SERVICES_HA_TC_NO + 1))
        self.__multichains_tcs_range = xmap_add(
                self.__services_ha_tcs_range[-1],
                range(1, len(gbp_config.multiple_chain_tcs.keys()) + 1))
        self.__gbp_cuds_tcs_range = xmap_add(
                self.__multichains_tcs_range[-1],
                range(1, len(gbp_config.gbp_crud_test_no_to_id_mapping.
                             keys()) + 1))
        self.__total_stress_tcs_range = self.__e2e_scenario_tcs_range +\
            self.__services_ha_tcs_range + self.__multichains_tcs_range +\
            self.__gbp_cuds_tcs_range
        self.__common_obj = commonLibrary()

    def __run_stress_test(self, stress_tcno_list):
        """It's thread function, called by different threads,
        to perform parallel insertions.

        :param list tc_no_list: list of stress test case numbers.
        """
        try:
            LOG_OBJ.debug("stress_tcno_list: %s" % stress_tcno_list)

            def tc_string(tcnos_list):
                """Map stress test to tests for features like e2e scenarios,
                service ha test, multiple chain tests.Returns test
                cases number string."""
                LOG_OBJ.debug("tcnos_list: %s" % tcnos_list)
                return ','.join([str(int(tc_no) - (tcnos_list[0] - 1))
                                 for tc_no in stress_tcno_list
                                 if int(tc_no) in tcnos_list])

            e2e_tcs = tc_string(self.__e2e_scenario_tcs_range)
            services_ha_tcs = tc_string(self.__services_ha_tcs_range)
            multichains_tcs = tc_string(self.__multichains_tcs_range)
            gbp_crud_tcs = tc_string(self.__gbp_cuds_tcs_range)

            LOG_OBJ.debug("e2e_tcs: %s" % e2e_tcs)
            LOG_OBJ.debug("services_ha_tcs: %s" % services_ha_tcs)
            LOG_OBJ.debug("multichains_tcs: %s" % multichains_tcs)
            LOG_OBJ.debug("gbp_crud_tcs: %s" % gbp_crud_tcs)

            if e2e_tcs:   # end to end scenarios.
                InsertionTests().master_testcase(e2e_tcs)
            if services_ha_tcs:   # services ha tests.
                ServicesHATest().services_ha_master_test(services_ha_tcs)
            if multichains_tcs:   # multiple chain tests.
                MultipleChain().multiple_chain_master(multichains_tcs)
            if gbp_crud_tcs:   # gbp rest api validation tests.
                GbpCrudsValidation().gbp_crud_master_testcase(gbp_crud_tcs)
            LOG_OBJ.debug("Test execution completed ...")
            StressTestHelper().advance_counter_exec_done()
            return True
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Some problem occurred while "\
                "stress tests execution."

    def stress_master(self, tc_no_string):
        """Stress master method.

        Arguments:
        :param string tc_no_string: test cases number string.
                e.g.
                    "1-300,301-348,349-379,380-392"
        """
        try:
            # get test cases number list.
            thread_count = self.get_thread_count()
            tcno_list = self.__common_obj.build_testcase_no_list(tc_no_string)
            LOG_OBJ.debug("Number of threads: %s" % thread_count)
            thread_list = []
            for th_no in range(thread_count):
                print "Creating thread..."
                LOG_OBJ.info("Creating thread...")
                tc_list_per_thread = tcno_list
                if gbp_config.load_sharing:
                    tc_list_per_thread =\
                        [tcno_list[tc_index] for tc_index in
                         range(th_no, len(tcno_list), thread_count)]

                thread = threading.Thread(
                            name=gbp_config.thread_name + str(th_no),
                            target=self.__run_stress_test,
                            args=(tc_list_per_thread,))
                print "Created Thread: %s" % thread.getName()
                LOG_OBJ.debug("Created Thread: %s" % thread.getName())
                LOG_OBJ.debug("Tests that will be executed by %s: %s"
                              % (thread.getName(), tc_list_per_thread))
                thread_list.append(thread)

            for thread in thread_list:
                thread.start()

            for thread in thread_list:
                thread.join()
            LOG_OBJ.info("Stress tests completed ...")
        except Exception as err:
            LOG_OBJ.exception(err)
            return "Some problem occurred while"\
                " running stress tests."
