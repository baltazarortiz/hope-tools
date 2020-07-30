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
import shlex

sys.path.append(os.path.join(isp_utils.getIspPrefix(), "runtime"))
import isp_load_image
import isp_pex_kernel

logger = logging.getLogger()

isp_prefix = isp_utils.getIspPrefix()

fpga = "refpipe"
processor = "rocket"

#################################
# Build/Install Reference PEX kernel
# Invoked by isp_install_policy
#################################

def defaultPexPath(policy_name, arch, extra):
    extra_args = parseExtra(extra)
    return os.path.join(isp_prefix, "ref-pex-kernel", isp_pex_kernel.pexKernelName(policy_name, fpga, processor))

def installTagMemHexdump(policy_name, output_dir):
    logger.debug("Building tag_mem_hexdump utility for reference model")

    env = dict(os.environ)

    env["FPGA"] = fpga
    env["PROCESSOR"] = processor

    if policy_name.endswith("-debug"):
        policy_name = policy_name.replace("-debug", "")
        env["DEBUG"] = "1"

    env["POLICY_NAME"] = policy_name

    build_log_path = os.path.join(output_dir, "build.log")
    build_log = open(build_log_path, "w+")
    pex_kernel_output_dir = os.path.join(output_dir, "pex-kernel")
    result = subprocess.call(["make", "install-tag_mem_hexdump"], stdout=build_log, stderr=subprocess.STDOUT,
                             cwd=pex_kernel_output_dir, env=env)
    build_log.close()

    if result != 0:
        logger.error("Failed to install tag_mem_hexdump")
        return False

    return True

def installPatchTaginfo(output_dir):
    logger.debug("Installing patch-taginfo utility for reference model")

    env = dict(os.environ)

    env["FPGA"] = fpga
    env["PROCESSOR"] = processor

    build_log_path = os.path.join(output_dir, "build.log")
    build_log = open(build_log_path, "w+")
    pex_kernel_output_dir = os.path.join(output_dir, "pex-kernel")
    result = subprocess.call(["make", "install-patch-taginfo"], stdout=build_log, stderr=subprocess.STDOUT,
                             cwd=pex_kernel_output_dir, env=env)
    build_log.close()

    if result != 0:
        logger.error("Failed to install patch-taginfo")
        return False

    return True

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

    chipyard_env_script_path = os.path.join(isp_prefix, "chipyard-ref-pipe", "env.sh")
    chipyard_env = source_env_script(chipyard_env_script_path)

    if not isp_pex_kernel.buildPexKernel(policy_name, output_dir, fpga,
                                         processor, extra_env=chipyard_env):
        return False

    if not installTagMemHexdump(policy_name, output_dir):
        return False

    if not installPatchTaginfo(output_dir):
        return False

    if not isp_pex_kernel.movePexKernel(policy_name, output_dir, fpga, processor):
        return False

    return True

def source_env_script(env_script_path):
    # https://stackoverflow.com/questions/3503719/emulating-bash-source-in-python
    env_keep = [b'LD_LIBRARY_PATH', b'CHIPYARD_TOOLCHAIN_SOURCED', b'MAKEFLAGS', b'PATH', b'RISCV']
    env_out = {}

    command = shlex.split("env -i bash -c 'source %s && env'" % env_script_path)
    proc = subprocess.Popen(command, stdout = subprocess.PIPE)
    for line in proc.stdout:
        (key, _, value) = line.partition(b"=")
        if key in env_keep:
            env_out[key] = value

    proc.communicate()

    return env_out

#################################
# Run local refpipe simulation
# Invoked by isp_run_app
#################################

def parseExtra(extra):
    parser = argparse.ArgumentParser(prog="isp_run_app ... -s refpipe -e")
    parser.add_argument("--no-log", action="store_true", help="Do not read from the TTYs. This disables exit handling and output logging")
    parser.add_argument("--stock", action="store_true", help="Use a stock (no PIPE) bitstream")
    parser.add_argument("--init-only", action="store_true", help="Build the kernel and generate the hex init without running on the simulator")

    if not extra:
        return parser.parse_args([])

    extra_dashed = []
    for e in extra:
        if e.startswith("+"):
            extra_dashed.append("--" + e[1:])
        else:
            extra_dashed.append(e)

    return parser.parse_args(extra_dashed)

def generateTagMemHexdump(tag_file_path, policy):
    policy = policy.strip("-debug")
    commented_hex_path = tag_file_path + ".commented.hex"
    loadable_hex_path = tag_file_path + ".loadable.hex"
    min_taginfo_path = tag_file_path + ".min"

    subprocess.call(["tag_mem_hexdump-" + policy, tag_file_path, commented_hex_path, loadable_hex_path, min_taginfo_path])

    return commented_hex_path, loadable_hex_path, min_taginfo_path

def tagInit(exe_path, run_dir, policy_dir, soc_cfg, arch, pex_kernel_path):

    tag_file_path = os.path.join(run_dir, "bininfo", os.path.basename(exe_path) + ".taginfo")

    logger.debug("Using PEX kernel at path: {}".format(pex_kernel_path))

    if not isp_utils.generateTagInfo(exe_path, run_dir, policy_dir, soc_cfg=soc_cfg, arch=arch):
        return False

    return True

def runPipe(exe_path, pex_log, hex_file_path, no_log, arch):

    logger.info("TODO: run reference model")

    return isp_utils.retVals.SUCCESS

def runStock(exe_path, ap, openocd_log_file, gdb_log_file,
             gdb_port, no_log, arch):
    logger.debug("TODO: run stock chipyard")
    # run RV32RocketConfig with binary

    return isp_utils.retVals.SUCCESS

def genTrace(exe_path, ap, openocd_log_file, gdb_log_file,
             gdb_port, no_log, arch):
    logger.info("TODO: generate trace")
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

    if not extra_args.stock:
        if not tagInit(exe_path, run_dir, policy_dir, soc_cfg,
                       arch, pex_path):
            return isp_utils.retVals.TAG_FAIL

        logger.info("Generating hex files")
        tag_file_path = os.path.join(run_dir, "bininfo", os.path.basename(exe_path) + ".taginfo")
        policy_name = os.path.basename(policy_dir)
        commented_hex_path, loadable_hex_path, min_taginfo_path = generateTagMemHexdump(tag_file_path, policy_name)

        app_name = exe_path.split(os.path.sep)[-1] 
        pex_source_dir = os.path.join(isp_prefix, "sources", "policies")
        if not patchTaginfo(min_taginfo_path, app_name, pex_path):
            return False

    if extra_args.init_only:
        return isp_utils.retVals.SUCCESS

    ap_log = open(ap_log_file, "w")
    pex_log = open(pex_log_file, "w")

    if extra_args.stock:
        result = runStock(exe_path, ap, openocd_log_file, gdb_log_file, gdb_port, extra_args.no_log, arch)
    else:
        result = runPipe(exe_path, pex_log, loadable_hex_path, extra_args.no_log, arch)

    pex_log.close()
    ap_log.close()

    return result

def patchTaginfo(tag_info_path, app_name, pex_path):
    # The reference PEX kernel includes a .taginfo section for the target AP
    # application, which is patched via objcopy after compilation 
    logger.debug("Patching PEX kernel with taginfo (%s) for %s" % (tag_info_path, app_name))

    result = subprocess.call(["patch-taginfo", tag_info_path, app_name, pex_path])

    if result != 0:
        logger.error("Failed to patch PEX kernel with taginfo")
        return False

    return True
