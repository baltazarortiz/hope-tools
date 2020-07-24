import isp_utils
import os
import argparse
import logging
import subprocess
import serial
import pexpect
import pexpect_serial
import threading
import sys
import time
import multiprocessing
import glob
import shutil

sys.path.append(os.path.join(isp_utils.getIspPrefix(), "runtime"))
import isp_load_image
import isp_pex_kernel

logger = logging.getLogger()

isp_prefix = isp_utils.getIspPrefix()

fpga = "verilator"
processor = "rocket"

#################################
# Build/Install Reference PEX kernel
# Invoked by isp_install_policy
#################################

def defaultPexPath(policy_name, arch, extra):
    extra_args = parseExtra(extra)
    return os.path.join(isp_prefix, "ref_pex_kernel", isp_pex_kernel.pexKernelName(policy_name, fpga,
                        "rocket"))

def installPex(policy_dir, output_dir, arch, extra):
    logger.info("Installing reference pex kernel for refpipe")
    pex_kernel_source_dir = os.path.join(isp_prefix, "sources", "ref-pex-kernel")
    policy_name = os.path.basename(policy_dir)

    extra_args = parseExtra(extra)

    if not isp_utils.checkDependency(pex_kernel_source_dir, logger):
        return False

    if not isp_pex_kernel.copyPexKernelSources(pex_kernel_source_dir, output_dir):
        return False

    if not isp_pex_kernel.copyPolicySources(policy_dir, output_dir, fpga, processor):
        return False

    logger.debug("TODO: auto-build ref pex kernel")
    #if not isp_pex_kernel.buildPexKernel(policy_name, output_dir, fpga, processor):
    #    return False

    logger.debug("TODO: auto-move ref pex kernel")
    #if not isp_pex_kernel.movePexKernel(policy_name, output_dir, fpga, processor):
    #    return False

    return True


#################################
# Run local refpipe simulation
# Invoked by isp_run_app
#################################

def parseExtra(extra):
    parser = argparse.ArgumentParser(prog="isp_run_app ... -s refpipe -e")
    parser.add_argument("--no-log", action="store_true", help="Do not read from the TTYs. This disables exit handling and output logging")
    parser.add_argument("--stock", action="store_true", help="Use a stock (no PIPE) bitstream")
    parser.add_argument("--init-only", action="store_true", help="Build the kernel and generate the hex init without running on the simulator")
    parser.add_argument("--hex-init", type=str, help="Pre-built hex init file")

    if not extra:
        return parser.parse_args([])

    extra_dashed = []
    for e in extra:
        if e.startswith("+"):
            extra_dashed.append("--" + e[1:])
        else:
            extra_dashed.append(e)

    return parser.parse_args(extra_dashed)

def tagInit(exe_path, run_dir, policy_dir, soc_cfg, arch, pex_kernel_path,
            hex_file_path):

    tag_file_path = os.path.join(run_dir, "bininfo", os.path.basename(exe_path) + ".taginfo")

    logger.debug("Using PEX kernel at path: {}".format(pex_kernel_path))

    if not isp_utils.generateTagInfo(exe_path, run_dir, policy_dir, soc_cfg=soc_cfg, arch=arch):
        return False

    logger.debug("Using hex file {}".format(hex_file_path))
    if not os.path.exists(hex_file_path):
        logger.info("TODO: Generate hex file")

        # cd tag_mem_hexdump
        # make
        # XXX: ./tag_mem_hexdump-rwx ../taginfo_tmp/hello_works_1.taginfo ../taginfo_tmp/hello_works_1_rwx.hexcomment ../taginfo_tmp/hello_works_1.hexload
        #isp_load_image.generate_flash_init(flash_init_image_path, flash_init_map)

    return True

def runPipe(exe_path, pex_log, hex_file_path, no_log, arch):

    logger.info("TODO: run reference model")

    return isp_utils.retVals.SUCCESS

def runStock(exe_path, ap, openocd_log_file, gdb_log_file,
             gdb_port, no_log, arch):
    logger.debug("TODO")
    # run RV32RocketConfig with binary

    return isp_utils.retVals.SUCCESS

def genTrace(exe_path, ap, openocd_log_file, gdb_log_file,
             gdb_port, no_log, arch):
    logger.info("TODO")
    # run RV32RocketConfig-debug, convert trace
    return None

def runSim(exe_path, run_dir, policy_dir, pex_path, runtime, rule_cache,
           gdb_port, tagfile, soc_cfg, arch, extra, use_validator=False):

    extra_args = parseExtra(extra)

    ap_log_file = os.path.join(run_dir, "uart.log")
    pex_log_file = os.path.join(run_dir, "pex.log")

    if not soc_cfg:
        soc_cfg = os.path.join(isp_prefix, "soc_cfg", "ref_cfg.yml")
    else:
        soc_cfg = os.path.realpath(soc_cfg)
    logger.debug("Using SOC config {}".format(soc_cfg))

    hex_file_path = os.path.join(run_dir, ".hexload")
    if extra_args.hex_init:
        hex_file_path = os.path.realpath(extra_args.hex_init)

    if not extra_args.stock:
        if not tagInit(exe_path, run_dir, policy_dir, soc_cfg,
                       arch, pex_path, hex_file_path):
            return isp_utils.retVals.TAG_FAIL

    if extra_args.init_only:
        return isp_utils.retVals.SUCCESS

    ap_log = open(ap_log_file, "w")
    pex_log = open(pex_log_file, "w")

    if extra_args.stock:
        result = runStock(exe_path, ap, openocd_log_file, gdb_log_file, gdb_port, extra_args.no_log, arch)
    else:
        result = runPipe(exe_path, pex_log, hex_file_path, extra_args.no_log, arch)

    pex_log.close()
    ap_log.close()

    return result
