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
chipyard_path = os.path.join(isp_prefix, "chipyard-ref-pipe")
chipyard_env_script_path = os.path.join(chipyard_path, "env.sh")
chipyard_run_path = os.path.join(chipyard_path, "sims", "verilator")
refpipe_generator_path = os.path.join(chipyard_path, "generators", "ref-pipe")

num_cores_str = str(multiprocessing.cpu_count())

fpga = "refpipe"
processor = "rocket"

#################################
# Build/Install Reference PEX kernel
# Invoked by isp_install_policy
#################################

def defaultPexPath(policy_name, arch, extra):
    extra_args = parseExtra(extra)
    return os.path.join(isp_prefix, "ref-pex-kernel", isp_pex_kernel.pexKernelName(policy_name, fpga, processor))

def printBuildInstructions(config, debug=True):
    cd_cmd = "cd " + chipyard_run_path
    source_cmd = "source " + chipyard_env_script_path

    build_cmd = "make -j%s CONFIG=%s" % (num_cores_str, config)
    if debug:
        build_cmd += " debug"

    build_instrs = "Please rerun this command after executing the following commands to build:\n\n%s\n%s\n%s" % (cd_cmd, source_cmd, build_cmd)

    logger.info(build_instrs)


def installTagMemHexdump(policy_name, output_dir):
    logger.info("Building tag_mem_hexdump utility for reference model")

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
    logger.info("Installing patch-taginfo utility for reference model")

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

def get_chipyard_env():
    env = dict(os.environ)
    for k, v in source_env_script(chipyard_env_script_path).items():
        k = str(k, 'utf-8')
        v = str(v, 'utf-8')

        # Append some keys, replace the rest
        if k in ('PATH', 'CFLAGS', 'LDFLAGS'):
            env[k] = v + env[k]
        else:
            env[k] = v

    return env

#################################
# Run local refpipe simulation
# Invoked by isp_run_app
#################################

def parseExtra(extra):
    parser = argparse.ArgumentParser(prog="isp_run_app ... -s refpipe -e")
    parser.add_argument("--no-log", action="store_true", help="Do not write logs / VCD waveforms during simulation")
    parser.add_argument("--stock", action="store_true", help="Use a stock (no PIPE) version of Chipyard")
    parser.add_argument("--init-only", action="store_true", help="Build the kernel and generate the hex init without running on the simulator")
    parser.add_argument("--debug", action="store_true", help="Generate waveforms and verbose logs for the main simulation. Note that trace generation must run in verbose mode.")

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
    logger.info("Running tag_mem_hexdump")
    policy = policy.strip("-debug")
    commented_hex_path = tag_file_path + ".commented.hex"
    loadable_hex_path = tag_file_path + ".loadable.hex"
    min_taginfo_path = tag_file_path + ".min"

    subprocess.call(["tag_mem_hexdump-" + policy, tag_file_path, commented_hex_path, loadable_hex_path, min_taginfo_path])

    return commented_hex_path, loadable_hex_path, min_taginfo_path

def tagInit(exe_path, run_dir, policy_dir, soc_cfg, arch, pex_kernel_path):
    logger.info("Tag init starting. Using PEX kernel at path: {}".format(pex_kernel_path))

    tag_file_path = os.path.join(run_dir, "bininfo", os.path.basename(exe_path) + ".taginfo")

    if not isp_utils.generateTagInfo(exe_path, run_dir, policy_dir, soc_cfg=soc_cfg, arch=arch):
        return False

    return True

# XXX: clean build option?
def runPipe(exe_path, pex_path, ap_log, pex_log, trace_path,
            hex_file_path, hex_file_address, no_log, debug, arch):

    # Default to 32 bit
    config = "RefPIPE32RocketConfig"
    if arch == "rv64":
        config = "RefPIPE64RocketConfig"

    # Default to no debug
    target = "run-binary-fast"
    refpipe_sim_path = os.path.join(chipyard_run_path, "simulator-chipyard-%s" % config)
    if debug:
        target = "run-binary-debug"
        refpipe_sim_path = os.path.join(chipyard_run_path, "simulator-chipyard-%s-debug" % config)

    if not(os.path.isfile(refpipe_sim_path)):
        logger.error("No reference model simulation binary found at %s!" % refpipe_sim_path)
        printBuildInstructions(config, debug=debug)
        return isp_utils.retVals.FAILURE

    logger.info("Running reference model simulation")

    env = get_chipyard_env()

    env["FPGA"] = fpga
    env["PROCESSOR"] = processor

    sim_flags = "+trace_file=%s +loadmem=%s +loadmem_addr=%s" % (trace_path, hex_file_path, hex_file_address)

    # TODO: add exe_path once AP + PEX both work on refpipe chipyard
    runpipe_cmd = ["make", target, "CONFIG=" + config, "BINARY=" + pex_path, "SIM_FLAGS=" + sim_flags]
    pex_log.write("Output generated by running:\n" + " ".join(runpipe_cmd))
    result = subprocess.call(runpipe_cmd,
                             stdout=pex_log, stderr=subprocess.STDOUT,
                             cwd=chipyard_run_path, env=env)

    if result != 0:
        logger.error("Failed to run refpipe Chipyard simulation")
        return isp_utils.retVals.FAILURE

    return isp_utils.retVals.SUCCESS

def runStock(exe_path, ap_log, no_log, arch):

    logger.info("Running stock Chipyard simulation")

    env = get_chipyard_env()

    env["FPGA"] = fpga
    env["PROCESSOR"] = processor

    # Default to 32 bit
    config = "RV32RocketConfig"
    if arch == "rv64":
        config = "RocketConfig"

    target = "run-binary-debug"
    if no_log:
        target = "run-binary-fast"

    result = subprocess.call(["make", target, "CONFIG=" + config, "BINARY=" + exe_path],
                             stdout=ap_log, stderr=subprocess.STDOUT,
                             cwd=chipyard_run_path, env=env)

    if result != 0:
        logger.error("Failed to run stock Chipyard simulation")
        return isp_utils.retVals.FAILURE

    return isp_utils.retVals.SUCCESS

def genTrace(exe_path, ap_log, run_log, arch):

    # Default to 32 bit
    config = "RV32PIPETraceConfig"
    if arch == "rv64":
        config = "RV32PIPETraceConfig"

    stock_rocket_sim_path = os.path.join(chipyard_run_path, "simulator-chipyard-%s-debug" % config)

    if not(os.path.isfile(stock_rocket_sim_path)):
        logger.error("No stock Chipyard simulation binary found at %s!" % stock_rocket_sim_path)
        printBuildInstructions(config, debug=True)
        return isp_utils.retVals.FAILURE

    app_name = exe_path.split(os.path.sep)[-1]
    chipyard_log_path = os.path.join(chipyard_run_path, "output", "chipyard.TestHarness." + config, app_name + ".out")
    refpipe_trace_path = os.path.join(chipyard_run_path, "output", "chipyard.TestHarness." + config, app_name + ".trace")

    if not os.path.isfile(refpipe_trace_path):
        logger.info("Generating trace using stock Chipyard simulation")

        env = get_chipyard_env()
        env["FPGA"] = fpga
        env["PROCESSOR"] = processor
        env["SHELL"] = "/bin/sh"

        result = subprocess.call(["make", "-j" + num_cores_str, "run-binary-debug", "CONFIG=" + config, "BINARY=" + exe_path],
                                 stdout=ap_log, stderr=subprocess.STDOUT,
                                 cwd=chipyard_run_path, env=env)

        if result != 0:
            logger.error("Failed to generate trace")
            return None

        convert_log_script = os.path.join(refpipe_generator_path, "convert_rocket_log.py")

        logger.info("Converting Rocket trace to refpipe format")
        result = subprocess.call(["python", convert_log_script, chipyard_log_path, refpipe_trace_path],
                                stdout=run_log, stderr=subprocess.STDOUT)

        if result != 0:
            logger.error("Failed to convert trace")
            return None
    else:
        logger.info("Using existing trace file at %s. If %s has been updated, delete this trace file and rerun this command." % (refpipe_trace_path, app_name))

    return refpipe_trace_path

def runSim(exe_path, run_dir, policy_dir, pex_path, runtime, rule_cache,
           gdb_port, tagfile, soc_cfg, arch, extra, use_validator=False):

    extra_args = parseExtra(extra)

    run_log_file = os.path.join(run_dir, "run.log")
    ap_log_file = os.path.join(run_dir, "uart.log")
    pex_log_file = os.path.join(run_dir, "pex.log")

    if not soc_cfg:
        soc_cfg = os.path.join(isp_prefix, "soc_cfg", "ref_cfg.yml")
    else:
        soc_cfg = os.path.realpath(soc_cfg)
    logger.info("Using SOC config {}".format(soc_cfg))

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
        patched_pex_path = patchTaginfo(min_taginfo_path, app_name, pex_path)
        if patched_pex_path is None:
            return False

    if extra_args.init_only:
        return isp_utils.retVals.SUCCESS

    run_log = open(run_log_file, "w")
    ap_log = open(ap_log_file, "w")
    pex_log = open(pex_log_file, "w")

    if extra_args.stock:
        result = runStock(exe_path, ap_log, extra_args.no_log, arch)
    else:
        trace_path = genTrace(exe_path, ap_log, run_log, arch)
        if trace_path is None:
            return isp_utils.retVals.FAILURE

        result = runPipe(exe_path, patched_pex_path, ap_log, pex_log, trace_path,
                         loadable_hex_path, "80000000", extra_args.no_log, extra_args.debug, arch)

    run_log.close()
    pex_log.close()
    ap_log.close()

    return result

def patchTaginfo(tag_info_path, app_name, pex_path):
    # The reference PEX kernel includes a .taginfo section for the target AP
    # application, which is patched via objcopy after compilation 
    logger.info("Patching PEX kernel with taginfo (%s) for %s" % (tag_info_path, app_name))

    result = subprocess.call(["patch-taginfo", tag_info_path, app_name, pex_path])

    if result != 0:
        logger.error("Failed to patch PEX kernel with taginfo")
        return None

    return pex_path + "-" + app_name
