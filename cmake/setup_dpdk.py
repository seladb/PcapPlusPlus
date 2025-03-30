#! /usr/bin/env python


# pylint: disable=missing-module-docstring,missing-function-docstring,missing-class-docstring,too-many-lines


import sys
import os
import json
import glob
import logging
import time
import argparse
import subprocess

# The PCI base class for all devices
network_class = {
    "Class": "02",
    "Vendor": None,
    "Device": None,
    "SVendor": None,
    "SDevice": None,
}
acceleration_class = {
    "Class": "12",
    "Vendor": None,
    "Device": None,
    "SVendor": None,
    "SDevice": None,
}
ifpga_class = {
    "Class": "12",
    "Vendor": "8086",
    "Device": "0b30",
    "SVendor": None,
    "SDevice": None,
}
encryption_class = {
    "Class": "10",
    "Vendor": None,
    "Device": None,
    "SVendor": None,
    "SDevice": None,
}
intel_processor_class = {
    "Class": "0b",
    "Vendor": "8086",
    "Device": None,
    "SVendor": None,
    "SDevice": None,
}
cavium_sso = {
    "Class": "08",
    "Vendor": "177d",
    "Device": "a04b,a04d",
    "SVendor": None,
    "SDevice": None,
}
cavium_fpa = {
    "Class": "08",
    "Vendor": "177d",
    "Device": "a053",
    "SVendor": None,
    "SDevice": None,
}
cavium_pkx = {
    "Class": "08",
    "Vendor": "177d",
    "Device": "a0dd,a049",
    "SVendor": None,
    "SDevice": None,
}
cavium_tim = {
    "Class": "08",
    "Vendor": "177d",
    "Device": "a051",
    "SVendor": None,
    "SDevice": None,
}
cavium_zip = {
    "Class": "12",
    "Vendor": "177d",
    "Device": "a037",
    "SVendor": None,
    "SDevice": None,
}
avp_vnic = {
    "Class": "05",
    "Vendor": "1af4",
    "Device": "1110",
    "SVendor": None,
    "SDevice": None,
}

octeontx2_sso = {
    "Class": "08",
    "Vendor": "177d",
    "Device": "a0f9,a0fa",
    "SVendor": None,
    "SDevice": None,
}
octeontx2_npa = {
    "Class": "08",
    "Vendor": "177d",
    "Device": "a0fb,a0fc",
    "SVendor": None,
    "SDevice": None,
}
octeontx2_dma = {
    "Class": "08",
    "Vendor": "177d",
    "Device": "a081",
    "SVendor": None,
    "SDevice": None,
}

intel_ioat_bdw = {
    "Class": "08",
    "Vendor": "8086",
    "Device": "6f20,6f21,6f22,6f23,6f24,6f25,6f26,6f27,6f2e,6f2f",
    "SVendor": None,
    "SDevice": None,
}
intel_ioat_skx = {
    "Class": "08",
    "Vendor": "8086",
    "Device": "2021",
    "SVendor": None,
    "SDevice": None,
}
intel_ntb_skx = {
    "Class": "06",
    "Vendor": "8086",
    "Device": "201c",
    "SVendor": None,
    "SDevice": None,
}

network_devices = [network_class, cavium_pkx, avp_vnic, ifpga_class]
baseband_devices = [acceleration_class]
crypto_devices = [encryption_class, intel_processor_class]
eventdev_devices = [cavium_sso, cavium_tim, octeontx2_sso]
mempool_devices = [cavium_fpa, octeontx2_npa]
compress_devices = [cavium_zip]
misc_devices = [intel_ioat_bdw, intel_ioat_skx, intel_ntb_skx, octeontx2_dma]

logger = logging.getLogger()

# global dict ethernet devices present. Dictionary indexed by PCI address.
# Each device within this is itself a dictionary of device properties
_DEVICES = {}  # pylint:disable=invalid-name

# list of supported DPDK drivers
_DPDK_DRIVERS = ["igb_uio", "vfio-pci", "uio_pci_generic"]

# setting file
_SETTINGS_FILE = "setup_dpdk_settings.dat"

# IP tools ("ip" or "ifconfig")
_IP_TOOLS = None


def usage():
    return """
    This tool helps setting up DPDK on your machine. It's based on the `dpdk-devbind`
    tool that is shipped with DPDK: <https://doc.dpdk.org/guides/tools/devbind.html>
    but extends its capabilities. It takes care of everything that is needed to run
    a DPDK application:
    - Allocate hugepages used by DPDK for packet buffer allocation
    - Insert DPDK kernel modules
    - [Optional] Install the DPDK KNI module
      (https://doc.dpdk.org/guides/prog_guide/kernel_nic_interface.html)
    - Bind devices from their "standard" drivers to DPDK-controlled drivers

    In addition this tool allows checking the status of the devices currently
    bound/unbound to DPDK (similar to `dpdk-devbind --status`).

    Last, it allows unsetting all DPDK configuration and restore the system to its
    previous state.

    The tool has 3 available options:

    setup
    -----

    Setup DPDK on your machine. This option expects as input several parameters such
    as the amount of hugepages to allocate, a list of (one or more) network interfaces
    to allocate for DPDK, the DPDK driver to use and more.
    After setup is complete the previous configuration is saved in the file
    `{settings_file}` which can later be used to restore the settings by the
    "restore" command.

    status
    ------

    Show the status of all network devices and for each device is shows whether it's
    used by DPDK driver or by a kernel driver (similar to `dpdk-devbind --status`).

    restore
    -------

    Restore the system to its previous state. This command assumes that the file
    `{settings_file}` exists and contains the information that was written by the
    "setup" command of the system configuration before DPDK setup.
    Please note that a machine restart will usually reset these configurations
    anyway (unless otherwise configured by the user). However this command is useful
    for restoring the system without a restart.

    Examples:
    =========

    [Setup] allocate 512 hugepages and bind interfaces `eth0` and `eth1` to DPDK:

        sudo python setup_dpdk.py setup -g 512 -i eth0 eth1

    [Setup] allocate 64 hugepages, bind `eth0` to DPDK and use the `uio_pci_generic`
    driver (the default if not specified is `igb_uio`):

        sudo python setup_dpdk.py setup -g 64 -i eth0 -m uio_pci_generic

    [Setup] allocate 1024 hugepages, bind `enp0s3` to DPDK and load the DPDK KNI
    driver (not loaded by default):

        sudo python setup_dpdk.py setup -g 1024 -i enp0s3 -k

    [Status]

        sudo python setup_dpdk.py status

    [Restore]

        sudo python setup_dpdk.py restore\n\n
    """.format(settings_file=_SETTINGS_FILE)


# This is roughly compatible with check_output function in subprocess module
# which is only available in python 2.7.
def check_output(args, stderr=None):
    """Run a command and capture its output"""
    logger.debug("running command: '%s'", " ".join(args))
    return subprocess.Popen(args, stdout=subprocess.PIPE, stderr=stderr).communicate()[
        0
    ]


def has_driver(dev_id):
    """return true if a device is assigned to a driver. False otherwise"""
    return "Driver_str" in _DEVICES[dev_id]


def get_pci_device_details(dev_id, probe_lspci):
    """This function gets additional details for a PCI device"""
    device = {}

    if probe_lspci:
        extra_info = check_output(["lspci", "-vmmks", dev_id]).splitlines()

        # parse lspci details
        for line in extra_info:
            if len(line) == 0:
                continue
            name, value = line.decode().split("\t", 1)
            name = name.strip(":") + "_str"
            device[name] = value
    # check for a unix interface name
    device["Interface"] = ""
    for base, dirs, _ in os.walk("/sys/bus/pci/devices/%s/" % dev_id):
        if "net" in dirs:
            device["Interface"] = ",".join(os.listdir(os.path.join(base, "net")))
            break
    # check if a port is used for ssh connection
    device["Ssh_if"] = False
    device["Active"] = ""

    return device


def clear_data():
    """This function clears any old data"""
    global _DEVICES  # pylint:disable=global-statement
    _DEVICES = {}


def get_device_details(devices_type):
    """This function populates the "_DEVICES" dictionary. The keys used are
    the pci addresses (domain:bus:slot.func). The values are themselves
    dictionaries - one for each NIC."""

    # pylint:disable=too-many-branches

    global _DEVICES  # pylint:disable=global-statement

    # first loop through and read details for all devices
    # request machine readable format, with numeric IDs and String
    dev = {}
    dev_lines = check_output(["lspci", "-Dvmmnnk"]).splitlines()
    for dev_line in dev_lines:
        if len(dev_line) == 0:
            if device_type_match(dev, devices_type):
                # Replace "Driver" with "Driver_str" to have consistency of
                # of dictionary key names
                if "Driver" in dev.keys():
                    dev["Driver_str"] = dev.pop("Driver")
                if "Module" in dev.keys():
                    dev["Module_str"] = dev.pop("Module")
                # use dict to make copy of dev
                _DEVICES[dev["Slot"]] = dict(dev)
            # Clear previous device's data
            dev = {}
        else:
            name, value = dev_line.decode().split("\t", 1)
            value_list = value.rsplit(" ", 1)
            if len(value_list) > 1:
                # String stored in <name>_str
                dev[name.rstrip(":") + "_str"] = value_list[0]
            # Numeric IDs
            dev[name.rstrip(":")] = (
                value_list[len(value_list) - 1].rstrip("]").lstrip("[")
            )

    if devices_type == network_devices:
        # check what is the interface if any for an ssh connection if
        # any to this host, so we can mark it later.
        ssh_if = []
        route = check_output(["ip", "-o", "route"])
        # filter out all lines for 169.254 routes
        route = "\n".join(
            filter(lambda ln: not ln.startswith("169.254"), route.decode().splitlines())
        )
        rt_info = route.split()
        for i in range(len(rt_info) - 1):
            if rt_info[i] == "dev":
                ssh_if.append(rt_info[i + 1])

    # based on the basic info, get extended text details
    for dev in _DEVICES:
        if not device_type_match(_DEVICES[dev], devices_type):
            continue

        # get additional info and add it to existing data
        _DEVICES[dev] = _DEVICES[dev].copy()
        # No need to probe lspci
        _DEVICES[dev].update(get_pci_device_details(dev, False).items())

        if devices_type == network_devices:
            for _if in ssh_if:
                if _if in _DEVICES[dev]["Interface"].split(","):
                    _DEVICES[dev]["Ssh_if"] = True
                    _DEVICES[dev]["Active"] = "*Active*"
                    break

        # add igb_uio to list of supporting modules if needed
        if "Module_str" in _DEVICES[dev]:
            for driver in _DPDK_DRIVERS:
                if driver not in _DEVICES[dev]["Module_str"]:
                    _DEVICES[dev]["Module_str"] = (
                        _DEVICES[dev]["Module_str"] + ",%s" % driver
                    )
        else:
            _DEVICES[dev]["Module_str"] = ",".join(_DPDK_DRIVERS)

        # make sure the driver and module strings do not have any duplicates
        if has_driver(dev):
            modules = _DEVICES[dev]["Module_str"].split(",")
            if _DEVICES[dev]["Driver_str"] in modules:
                modules.remove(_DEVICES[dev]["Driver_str"])
                _DEVICES[dev]["Module_str"] = ",".join(modules)


def device_type_match(dev, devices_type):
    # pylint:disable=too-many-nested-blocks
    for _, device_type in enumerate(devices_type):
        param_count = len([x for x in device_type.values() if x is not None])
        match_count = 0
        if dev["Class"][0:2] == device_type["Class"]:
            match_count = match_count + 1
            for key in device_type:
                if key != "Class" and device_type[key]:
                    value_list = device_type[key].split(",")
                    for value in value_list:
                        if value.strip(" ") == dev[key]:
                            match_count = match_count + 1
            # count must be the number of non None parameters to match
            if match_count == param_count:
                return True
    return False


def dev_id_from_dev_name(dev_name):
    """Take a device "name" - a string passed in by user to identify a NIC
    device, and determine the device id - i.e. the domain:bus:slot.func - for
    it, which can then be used to index into the devices array"""

    # check if it's already a suitable index
    if dev_name in _DEVICES:
        return dev_name

    # check if it's an index just missing the domain part
    if "0000:" + dev_name in _DEVICES:
        return "0000:" + dev_name

    # check if it's an interface name, e.g. eth1
    for dev in _DEVICES:
        if dev_name in _DEVICES[dev]["Interface"].split(","):
            return _DEVICES[dev]["Slot"]

    # if nothing else matches - error
    raise ValueError(
        'Unknown device: %s. Please specify device in "bus:slot.func" format' % dev_name
    )


def unbind_one(dev_id, quiet, force):
    def handle_error(error_msg):
        if not quiet:
            logger.error(error_msg)

    # Unbind the device identified by "dev_id" from its current driver
    dev = _DEVICES[dev_id]
    if not has_driver(dev_id):
        handle_error(
            "notice: %s %s %s is not currently managed by any driver"
            % (dev["Slot"], dev["Device_str"], dev["Interface"])
        )
        return

    # prevent us disconnecting ourselves
    if dev["Ssh_if"] and not force:
        handle_error(
            "routing table indicates that interface %s is active. "
            "Skipping unbind" % dev_id
        )
        return

    # write to /sys to unbind
    filename = "/sys/bus/pci/drivers/%s/unbind" % dev["Driver_str"]
    try:
        file_d = open(filename, "a")
    except Exception:
        handle_error(
            "Error: unbind failed for %s - Cannot open %s" % (dev_id, filename)
        )
    file_d.write(dev_id)
    logger.debug("unbind_one: write '%s' to '%s'", dev_id, filename)
    file_d.close()


def bind_one(dev_id, driver, quiet, force):
    """Bind the device given by "dev_id" to the driver "driver". If the device
    is already bound to a different driver, it will be unbound first"""

    # pylint:disable=too-many-return-statements,too-many-branches,too-many-statements

    def handle_error(error_msg):
        if not quiet:
            logger.error(error_msg)

    dev = _DEVICES[dev_id]
    saved_driver = None  # used to rollback any unbind in case of failure

    # prevent disconnection of our ssh session
    if dev["Ssh_if"] and not force:
        handle_error(
            "Warning: routing table indicates that interface %s is active. Not modifying"
            % dev_id
        )
        return None

    # unbind any existing drivers we don't want
    if has_driver(dev_id):
        if dev["Driver_str"] == driver:
            handle_error(
                "Notice: %s already bound to driver %s, skipping" % (dev_id, driver)
            )
            return None

        saved_driver = dev["Driver_str"]
        unbind_one(dev_id, quiet, force)
        dev.pop("Driver_str")  # pop driver string

    # For kernels >= 3.15 driver_override can be used to specify the driver
    # for a device rather than relying on the driver to provide a positive
    # match of the device.  The existing process of looking up
    # the vendor and device ID, adding them to the driver new_id,
    # will erroneously bind other devices too which has the additional burden
    # of unbinding those devices
    filename = "/sys/bus/pci/devices/%s/driver_override" % dev_id
    if os.path.exists(filename):
        try:
            file_d = open(filename, "w")
        except Exception:
            handle_error(
                "Error: bind failed for %s - Cannot open %s" % (dev_id, filename)
            )
            return None
        try:
            file_d.write("%s" % driver)
            logger.debug("bind_one: write '%s' to '%s'", driver, filename)
            file_d.close()
        except Exception:
            handle_error(
                "Error: bind failed for %s - Cannot write driver %s to "
                "PCI ID " % (dev_id, driver)
            )
            return None
    # For kernels < 3.15 use new_id to add PCI id's to the driver
    else:
        filename = "/sys/bus/pci/drivers/%s/new_id" % driver
        try:
            file_d = open(filename, "w")
        except Exception:
            handle_error(
                "Error: bind failed for %s - Cannot open %s" % (dev_id, filename)
            )
            return None
        try:
            # Convert Device and Vendor Id to int to write to new_id
            file_d.write("%04x %04x" % (int(dev["Vendor"], 16), int(dev["Device"], 16)))
            file_d.close()
        except Exception:
            handle_error(
                "Error: bind failed for %s - Cannot write new PCI ID to "
                "driver %s" % (dev_id, driver)
            )
            return None

    # do the bind by writing to /sys
    filename = "/sys/bus/pci/drivers/%s/bind" % driver
    try:
        file_d = open(filename, "a")
    except Exception:
        logger.error("Error: bind failed for %s - Cannot open %s", dev_id, filename)
        if saved_driver is not None:  # restore any previous driver
            bind_one(dev_id, saved_driver, quiet, force)
        return None
    try:
        file_d.write(dev_id)
        logger.debug("bind_one: write '%s' to '%s'", dev_id, filename)
        file_d.close()
    except Exception:
        # for some reason, closing dev_id after adding a new PCI ID to new_id
        # results in IOError. however, if the device was successfully bound,
        # we don't care for any errors and can safely ignore IOError
        tmp = get_pci_device_details(dev_id, True)
        if "Driver_str" in tmp and tmp["Driver_str"] == driver:
            return saved_driver
        logger.error(
            "Error: bind failed for %s - Cannot bind to driver %s", dev_id, driver
        )
        if saved_driver is not None:  # restore any previous driver
            bind_one(dev_id, saved_driver, quiet, force)
        return None

    # For kernels > 3.15 driver_override is used to bind a device to a driver.
    # Before unbinding it, overwrite driver_override with empty string so that
    # the device can be bound to any other driver
    filename = "/sys/bus/pci/devices/%s/driver_override" % dev_id
    if os.path.exists(filename):
        try:
            file_d = open(filename, "w")
        except Exception:
            handle_error(
                "Error: unbind failed for %s - Cannot open %s" % (dev_id, filename)
            )
            return None
        try:
            file_d.write("\00")
            logger.debug("bind_one: write '\00' to '%s'", filename)
            file_d.close()
        except Exception:
            handle_error(
                "Error: unbind failed for %s - Cannot open %s" % (dev_id, filename)
            )
            return None

    return saved_driver


def display_devices(title, dev_list, extra_params=None):
    """Displays to the user the details of a list of devices given in
    "dev_list". The "extra_params" parameter, if given, should contain a string
     with %()s fields in it for replacement by the named fields in each
     device's dictionary."""
    strings = []  # this holds the strings to print. We sort before printing
    print("\n%s" % title)
    print("=" * len(title))
    if len(dev_list) == 0:
        strings.append("<none>")
    else:
        for dev in dev_list:
            if extra_params is not None:
                strings.append(
                    "%s '%s %s' %s"
                    % (
                        dev["Slot"],
                        dev["Device_str"],
                        dev["Device"],
                        extra_params % dev,
                    )
                )
            else:
                strings.append("%s '%s'" % (dev["Slot"], dev["Device_str"]))
    # sort before printing, so that the entries appear in PCI order
    strings.sort()
    print("\n".join(strings))  # print one per line


def show_device_status(devices_type, device_name):
    kernel_drv = []
    dpdk_drv = []
    no_drv = []

    # split our list of network devices into the three categories above
    for dev in _DEVICES:
        if device_type_match(_DEVICES[dev], devices_type):
            if not has_driver(dev):
                no_drv.append(_DEVICES[dev])
                continue
            if _DEVICES[dev]["Driver_str"] in _DPDK_DRIVERS:
                dpdk_drv.append(_DEVICES[dev])
            else:
                kernel_drv.append(_DEVICES[dev])

    n_devs = len(dpdk_drv) + len(kernel_drv) + len(no_drv)

    # don't bother displaying anything if there are no devices
    if n_devs == 0:
        msg = "No '%s' devices detected" % device_name
        print("")
        print(msg)
        print("".join("=" * len(msg)))
        return

    # print each category separately, so we can clearly see what's used by DPDK
    if len(dpdk_drv) != 0:
        display_devices(
            "%s devices using DPDK-compatible driver" % device_name,
            dpdk_drv,
            "drv=%(Driver_str)s unused=%(Module_str)s",
        )
    if len(kernel_drv) != 0:
        display_devices(
            "%s devices using kernel driver" % device_name,
            kernel_drv,
            "if=%(Interface)s drv=%(Driver_str)s unused=%(Module_str)s %(Active)s",
        )
    if len(no_drv) != 0:
        display_devices(
            "Other %s devices" % device_name, no_drv, "unused=%(Module_str)s"
        )


def show_status(status_dev):
    """Function called when the script is passed the "--status" option.
    Displays to the user what devices are bound to the igb_uio driver, the
    kernel driver or to no driver"""

    if status_dev in ("net", "all"):
        show_device_status(network_devices, "Network")

    if status_dev in ("baseband", "all"):
        show_device_status(baseband_devices, "Baseband")

    if status_dev in ("crypto", "all"):
        show_device_status(crypto_devices, "Crypto")

    if status_dev in ("event", "all"):
        show_device_status(eventdev_devices, "Eventdev")

    if status_dev in ("mempool", "all"):
        show_device_status(mempool_devices, "Mempool")

    if status_dev in ("compress", "all"):
        show_device_status(compress_devices, "Compress")

    if status_dev in ("misc", "all"):
        show_device_status(misc_devices, "Misc (rawdev)")


def load_device_data():
    clear_data()
    get_device_details(network_devices)
    get_device_details(baseband_devices)
    get_device_details(crypto_devices)
    get_device_details(eventdev_devices)
    get_device_details(mempool_devices)
    get_device_details(compress_devices)
    get_device_details(misc_devices)


def is_mount(mount_path):
    with open("/proc/mounts", "r") as mounts:
        for line in mounts:
            if mount_path in line.split():
                return True
    return False


def find_and_set_rte_sdk(args, settings):
    if args.rte_sdk:
        settings.rte_sdk = args.rte_sdk
        return

    if os.environ.get("RTE_SDK"):
        settings.rte_sdk = os.environ.get("RTE_SDK")
        return

    if hasattr(settings, "rte_sdk") and settings.rte_sdk:
        return

    raise RuntimeError(
        "Cannot find RTE_SDK. Searched in the settings file, OS env variables and command-line arguments"
    )


def verify_rte_sdk(args, settings):
    find_and_set_rte_sdk(args, settings)
    if not os.path.exists(settings.rte_sdk):
        raise FileExistsError("RTE_SDK path: '%s' does not exist" % settings.rte_sdk)


def check_huge_pages():
    with open("/proc/meminfo", "r") as meminfo:
        for line in meminfo:
            if line.startswith("HugePages_Total"):
                return line.split()[1]
    return 0


def setup_huge_pages(amount):
    if check_huge_pages() == amount:
        return

    nr_hugepages_path = "/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages"
    with open(nr_hugepages_path, "w") as nr_huge:
        nr_huge.write(str(amount))

    mount_dir = "/mnt/huge"
    if not is_mount(mount_dir):
        check_output(["mount", "-t", "hugetlbfs", "nodev", mount_dir])

    logger.info("set up hugepages to %s", amount)


def restore_huge_pages():
    if check_huge_pages() == 0:
        return

    nr_hugepages_path = "/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages"
    with open(nr_hugepages_path, "w") as nr_huge:
        nr_huge.write("0")

    mount_dir = "/mnt/huge"
    if is_mount(mount_dir):
        check_output(["umount", mount_dir])

    logger.info("removed hugepages")


def is_module_loaded(module):
    for line in check_output(["lsmod"]).decode("utf-8").splitlines():
        if module in line.split():
            return True
    return False


def load_dpdk_module(module, settings):
    if is_module_loaded(module):
        logger.info("module '%s' already loaded", module)
        return

    if module in ["uio_pci_generic", "vfio-pci"]:
        output = check_output(["modprobe", module], stderr=subprocess.STDOUT)
        if output:
            raise RuntimeError(
                "Something went wrong with adding '%s' kernel module: %s"
                % (module, output.decode("utf-8"))
            )
        settings.dpdk_module = module
        logger.info("loaded kernel module '%s'", module)
    elif module == "igb_uio":
        if not hasattr(settings, "rte_sdk") or not settings.rte_sdk:
            raise RuntimeError("Cannot find RTE_SDK value in '%s'" % _SETTINGS_FILE)
        output = check_output(["modprobe", "uio"], stderr=subprocess.STDOUT)
        if output:
            raise RuntimeError(
                "Something went wrong with adding 'uio' kernel module: %s"
                % output.decode("utf-8")
            )
        logger.info("loaded kernel module 'uio'")
        output = check_output(
            ["insmod", "%s/build/kmod/igb_uio.ko" % settings.rte_sdk],
            stderr=subprocess.STDOUT,
        )
        if output:
            output = check_output(
                ["modprobe", "igb_uio"],
                stderr=subprocess.STDOUT,
            )
            if output:
                raise RuntimeError(
                    "Something went wrong with adding 'igb_uio' kernel module: %s"
                    % output.decode("utf-8")
                )
        settings.dpdk_module = module
        logger.info("loaded DPDK kernel module 'igb_uio'")
    else:
        raise RuntimeError("Module '%s' is not supported" % module)

    settings.dpdk_module = module


def remove_dpdk_module(module, settings):
    if not module:
        settings.dpdk_module = None
        return

    if not is_module_loaded(module):
        logger.warning("DPDK module not loaded")
        settings.dpdk_module = None
        return

    if module in ["uio_pci_generic", "vfio-pci"]:
        output = check_output(["modprobe", "-r", module], stderr=subprocess.STDOUT)
        if output:
            raise RuntimeError(
                "Something went wrong with removing '%s' kernel module: %s"
                % (module, output.decode("utf-8"))
            )
        logger.info("removed kernel module '%s'", module)
    elif module == "igb_uio":
        output = check_output(["rmmod", "igb_uio"], stderr=subprocess.STDOUT)
        if output:
            raise RuntimeError(
                "Something went wrong with removing 'igb_uio' kernel module: %s"
                % output.decode("utf-8")
            )
        logger.info("removed 'igb_uio' kernel module")

    settings.dpdk_module = None


def insert_kni_module(args, settings):
    kni_module = "rte_kni"

    if is_module_loaded(kni_module):
        logger.info("KNI module already loaded")
        return

    if not hasattr(settings, "rte_sdk") or not settings.rte_sdk:
        raise RuntimeError("Cannot find RTE_SDK value in '%s'" % _SETTINGS_FILE)

    kni_module_path = glob.glob(
        f"{settings.rte_sdk}/**/{kni_module}.ko", recursive=True
    )
    if not kni_module_path:
        raise RuntimeError(f"Cannot find KNI kernel module {kni_module}")

    kmod_params = args.kni_params
    output = check_output(
        ["insmod", kni_module_path[0], kmod_params],
        stderr=subprocess.STDOUT,
    )
    if output:
        raise RuntimeError(
            "Something went wrong with adding KNI kernel module: %s"
            % output.decode("utf-8")
        )
    settings.kni_module = kni_module
    logger.info("loaded KNI module")


def remove_kni_module(settings):
    kni_module = "rte_kni"

    if not is_module_loaded(kni_module):
        logger.warning("KNI module not loaded")
        settings.kni_module = None
        return

    output = check_output(["rmmod", kni_module], stderr=subprocess.STDOUT)
    if output:
        raise RuntimeError(
            "Something went wrong with removing KNI module: %s" % output.decode("utf-8")
        )
    logger.info("removed KNI kernel module")
    settings.kni_module = None


def get_interface_command(interface, up_or_down):
    if _IP_TOOLS == "ip":
        return ["ip", "link", "set", "dev", interface, up_or_down]
    return ["ifconfig", interface, up_or_down]


def set_interfaces_down(interfaces, settings):
    for interface in interfaces:
        output = check_output(
            get_interface_command(interface, "down"), stderr=subprocess.STDOUT
        )
        if output:
            if (  # pylint:disable=using-constant-test
                # pylint:disable=bad-continuation
                msg in output.decode("utf-8")
                for msg in ["No such device", "Cannot find device"]
            ):
                raise RuntimeError("Cannot find interface '%s'" % interface)
            raise RuntimeError(
                "Cannot shut down interface %s: %s"
                % (interface, output.decode("utf-8"))
            )
        logger.info("set interface '%s' down", interface)

    settings.interfaces = json.dumps(interfaces)


def set_interfaces_up(interfaces, settings):
    for interface in interfaces:
        output = check_output(
            get_interface_command(interface, "up"), stderr=subprocess.STDOUT
        )
        if output:
            if "No such device" in output.decode("utf-8"):
                raise RuntimeError("cannot find interface '%s'" % interface)
            logger.error(
                "error restoring interface '%s': %s", interface, output.decode("utf-8")
            )
        else:
            logger.info("restored interface '%s'", interface)

    settings.interfaces = None


def is_bound_to_driver(dev_id, driver):
    dev = _DEVICES[dev_id]
    return has_driver(dev_id) and dev["Driver_str"] == driver


def bind_interfaces(dpdk_module, interfaces, interface_infos, settings):
    load_device_data()
    for interface in interfaces:
        try:
            dev_id = dev_id_from_dev_name(interface)
        except ValueError:
            raise RuntimeError(  # pylint:disable=raising-format-tuple
                "cannot find interface '%s'", interface
            )

        # check if the device is already bound to the driver
        if is_bound_to_driver(dev_id, dpdk_module):
            logger.info(
                "interface '%s' is already bound to DPDK driver '%s'",
                interface,
                dpdk_module,
            )

            interface_infos.append(
                {"dev_id": dev_id, "saved_driver": _DEVICES[dev_id]["Module_str"]}
            )
            continue

        # if device is not bound, bind it
        saved_driver = bind_one(dev_id, dpdk_module, quiet=False, force=False)
        if saved_driver:
            interface_infos.append(
                {
                    "dev_id": dev_id,
                    "saved_driver": saved_driver,
                }
            )
            logger.info(
                "bound interface '%s' ['%s'] to '%s'", interface, dev_id, dpdk_module
            )
        else:
            raise RuntimeError("Error binding interface '%s'" % interface)

    settings.interface_infos = json.dumps(interface_infos)


def unbind_interfaces(interface_infos, settings):
    load_device_data()
    for interface_info in interface_infos:
        bind_one(
            interface_info["dev_id"],
            interface_info["saved_driver"],
            quiet=True,
            force=False,
        )
        logger.info(
            "bound device '%s' back to '%s'",
            interface_info["dev_id"],
            interface_info["saved_driver"],
        )
    settings.interface_infos = None


def do_restore(dpdk_module, interfaces, interface_infos, settings, kni_module=None):
    try:
        restore_huge_pages()
        unbind_interfaces(interface_infos, settings)
        time.sleep(1)
        set_interfaces_up(interfaces, settings)
        remove_dpdk_module(dpdk_module, settings)
        if kni_module:
            remove_kni_module(settings)
    except PermissionError:
        logger.error("insufficient privileges. Please run this utility as 'sudo'")
        raise
    except Exception as exc:
        logger.error("error restoring system: %s", exc)
        raise exc


def handle_restore(_args, settings):
    dpdk_module = getattr(settings, "dpdk_module", None)
    kni_module = getattr(settings, "kni_module", None)
    interfaces = json.loads(getattr(settings, "interfaces", "[]"))
    interface_infos = json.loads(getattr(settings, "interface_infos", "[]"))
    do_restore(
        dpdk_module, interfaces, interface_infos, settings, kni_module=kni_module
    )
    logger.info("RESTORE COMPLETE")


def handle_setup(args, settings):
    interface_infos = []
    try:
        verify_rte_sdk(args, settings)
    except Exception as exc:
        logger.error(exc)
        raise

    try:
        setup_huge_pages(args.huge_pages)
        load_dpdk_module(args.dpdk_module, settings)
        if args.load_kni:
            insert_kni_module(args, settings)
        set_interfaces_down(args.interface, settings)
        bind_interfaces(args.dpdk_module, args.interface, interface_infos, settings)
        logger.info("SETUP COMPLETE")
    except PermissionError:
        logger.error("insufficient privileges. Please run this utility as 'sudo'")
        raise
    except Exception as exc:
        logger.error(exc)
        logger.error("restoring settings:")
        do_restore(
            args.dpdk_module,
            args.interface,
            interface_infos,
            settings,
            kni_module=args.load_kni,
        )
        raise exc


def handle_status(_args, _settings):
    show_status("all")


def parse_args():
    parser = argparse.ArgumentParser(
        description=usage(), formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(title="Available options", dest="cmd")
    subparsers.required = True

    parser_setup = subparsers.add_parser("setup", help="setup DPDK on your machine")
    parser_setup.set_defaults(func=handle_setup)
    parser_setup.add_argument(
        "-g",
        "--huge-pages",
        metavar="AMOUNT",
        type=int,
        required=True,
        help="amount of huge pages to allocate (huge pages are needed for DPDK's memory allocations)",  # pylint:disable=line-too-long
    )
    parser_setup.add_argument(
        "-i",
        "--interface",
        metavar="NIC_NAME",
        type=str,
        nargs="+",
        required=True,
        help="the name of a network interface (e.g eth1) that will be unbound from Linux and move to DPDK control",  # pylint:disable=line-too-long
    )
    parser_setup.add_argument(
        "-m",
        "--dpdk-module",
        choices=["igb_uio", "uio_pci_generic", "vfio-pci"],
        default="igb_uio",
        help="the DPDK module to install. If not specified the default is 'igb_uio'",
    )
    parser_setup.add_argument(
        "-k",
        "--load-kni",
        action="store_true",
        help="install the KNI kernel module (not loaded by default)",
    )
    parser_setup.add_argument(
        "-p",
        "--kni-params",
        type=str,
        default="carrier=on",
        help="optional parameters for installing the KNI kernel module",
    )
    parser_setup.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="print more verbose output",
    )
    parser_setup.add_argument(
        "-r",
        "--rte-sdk",
        type=str,
        help="DPDK home directory",
    )

    parser_status = subparsers.add_parser(
        "status", help="display current Ethernet device settings"
    )
    parser_status.set_defaults(func=handle_status)
    parser_status.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="print more verbose output",
    )

    parser_restore = subparsers.add_parser(
        "restore", help="tear down DPDK and restore the system to its original state"
    )
    parser_restore.set_defaults(func=handle_restore)
    parser_restore.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="print more verbose output",
    )

    return parser.parse_args()


def init_logger(args):
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    log_format = "[%(levelname)s] %(message)s"
    formatter = logging.Formatter(log_format)
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)


class Settings:
    @classmethod
    def load(cls, settings_file_path):
        settings = cls()
        if os.path.exists(settings_file_path):
            logger.debug("loading from settings file '%s':", settings_file_path)
            with open(settings_file_path, "r") as settings_file:
                for line in settings_file.readlines():
                    line = line.rstrip()
                    if line:
                        logger.debug("  %s", line)
                        [key, value] = line.split("=")
                        setattr(settings, key.lower(), value)
        return settings

    def save(self, settings_file_path):
        with open(settings_file_path, "w") as settings_file:
            logger.debug("saving to settings file '%s':", settings_file_path)
            for attr, value in self.__dict__.items():
                if value:
                    line = "%s=%s" % (attr.upper(), value)
                    logger.debug("  %s", line)
                    settings_file.write("{line}\n".format(line=line))


def main():
    global _IP_TOOLS  # pylint:disable=global-statement

    # check if lspci is installed, suppress any output
    with open(os.devnull, "w") as devnull:
        if subprocess.call(["which", "lspci"], stdout=devnull, stderr=devnull) != 0:
            sys.exit("'lspci' not found - please install 'pciutils'")
        ip_installed = (
            subprocess.call(["which", "ip"], stdout=devnull, stderr=devnull) == 0
        )
        ifconfig_installed = (
            subprocess.call(["which", "ifconfig"], stdout=devnull, stderr=devnull) == 0
        )
        if ip_installed:
            _IP_TOOLS = "ip"
        elif ifconfig_installed:
            _IP_TOOLS = "ifconfig"
        else:
            sys.exit(
                "both 'ip' and 'ifconfig' are not found - please install one of them"
            )

    load_device_data()
    args = parse_args()
    init_logger(args)
    settings_file_full_path = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        _SETTINGS_FILE,
    )
    settings = Settings.load(settings_file_full_path)
    try:
        args.func(args, settings)
        settings.save(settings_file_full_path)
    except Exception:
        pass


if __name__ == "__main__":
    main()
